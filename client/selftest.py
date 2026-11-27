#!/usr/bin/env python3
"""selftest.py — Prueba E2E del relay desde el propio runner.

Abre una sesión a api.telegram.org:443 A TRAVÉS del túnel (bucket real),
completa un handshake TLS 1.3, hace GET / y getMe del bot por el túnel,
y notifica el resultado al grupo de Telegram (por conexión directa).

Env:
  RELAY_BASE_URL      base del bucket (p.ej. https://s3.todus.cu/public)
  PROXY_SHARED_SECRET secreto compartido (hex, >= 32 bytes)
  TG_BOT_TOKEN        (opcional) token del bot para getMe + notificar
  TG_GROUP_ID         (opcional) grupo al que notificar el resultado
"""

import json
import os
import ssl
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from relay_client import RelayError, RelaySocket, RelayStore  # noqa: E402


def notify_direct(token, chat_id, text):
    """Notifica al grupo por conexión DIRECTA (no por el túnel)."""
    if not token or not chat_id:
        return False
    try:
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=json.dumps({"chat_id": chat_id, "text": text,
                             "link_preview_options": {"is_disabled": True}}).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "curl/8.23.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode()).get("ok", False)
    except Exception as e:  # noqa: BLE001
        print(f"(notificación directa falló: {e})")
        return False


def read_until(sock, tls, incoming, min_bytes=1, timeout=20.0):
    """Lee bytes descifrados del túnel hasta EOF, timeout o min_bytes."""
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = tls.read(65536)
            if chunk:
                buf += chunk
                if len(buf) >= min_bytes and b"\r\n\r\n" in buf:
                    return buf
                continue
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLZeroReturnError:
            return buf
        raw = sock.recv(65536, timeout=5.0)
        if raw:
            incoming.write(raw)
        elif sock.remote_closed:
            # drenar lo descifrado pendiente
            try:
                while True:
                    chunk = tls.read(65536)
                    if not chunk:
                        break
                    buf += chunk
            except Exception:  # noqa: BLE001
                pass
            return buf
    return buf


def dbg(name, store, extra=None):
    """Escribe un marcador de progreso en el bucket (legible en vivo)."""
    try:
        obj = {"step": name, "ts": round(time.time()),
               "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        if extra:
            obj.update(extra)
        store.put("_v2_dbg_step.json", json.dumps(obj, ensure_ascii=False).encode())
    except Exception:  # noqa: BLE001
        pass


def main():
    base = os.environ.get("RELAY_BASE_URL", "https://s3.todus.cu/public")
    secret = os.environ.get("PROXY_SHARED_SECRET", "")
    token = os.environ.get("TG_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TG_GROUP_ID", "").strip()

    t_total0 = time.time()
    result = {"ok": False, "connect_ms": None, "tls_hs_ms": None,
              "getme": False, "http_status": None, "error": None}

    store = RelayStore(base, secret, http_timeout=30.0)
    sock = None
    dbg("inicio", store)
    try:
        # 1) sesión por el túnel hasta api.telegram.org:443
        t0 = time.time()
        sock = RelaySocket(store, chunk_size=131072, window=32, ack_every=8)
        sock.connect("api.telegram.org", 443, timeout=30.0)
        result["connect_ms"] = round((time.time() - t0) * 1000)
        print(f"[1/3] sesión relay ready ({result['connect_ms']} ms) id={sock.id}", flush=True)
        dbg("connect_ok", store, {"connect_ms": result["connect_ms"]})

        # 2) TLS 1.3 por el túnel (MemoryBIO + SSLObject)
        t0 = time.time()
        ctx = ssl.create_default_context()
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = ctx.wrap_bio(incoming, outgoing, server_hostname="api.telegram.org")
        handshake_done = False
        hs_deadline = time.time() + 25
        while not handshake_done and time.time() < hs_deadline:
            try:
                tls.do_handshake()
                handshake_done = True
                break
            except ssl.SSLWantReadError:
                if outgoing.pending:
                    sock.send(outgoing.read())
                data = sock.recv(65536, timeout=10.0)
                if not data:
                    raise RelayError("EOF durante handshake TLS (destino cerró: ¿RST/timeout del edge?)")
                incoming.write(data)
            except ssl.SSLWantWriteError:
                sock.send(outgoing.read())
        if not handshake_done:
            raise RelayError("timeout en handshake TLS")
        result["tls_hs_ms"] = round((time.time() - t0) * 1000)
        proto = tls.version()
        print(f"[2/3] handshake TLS por el túnel OK ({result['tls_hs_ms']} ms, {proto})", flush=True)
        dbg("tls_ok", store, {"tls_hs_ms": result["tls_hs_ms"], "proto": proto})

        # 3) HTTP: GET / y getMe por el túnel
        def tls_send(raw_request):
            tls.write(raw_request)
            while outgoing.pending:
                sock.send(outgoing.read())

        if token:
            path = f"/bot{token}/getMe"
        else:
            path = "/"
        tls_send(b"GET " + path.encode() + b" HTTP/1.1\r\n"
                 b"Host: api.telegram.org\r\n"
                 b"User-Agent: curl/8.23.0\r\n"
                 b"Accept: */*\r\n"
                 b"Connection: close\r\n\r\n")
        body = read_until(sock, tls, incoming, min_bytes=64, timeout=20)
        if not body:
            raise RelayError("respuesta HTTP vacía")
        head, _, payload = body.partition(b"\r\n\r\n")
        try:
            status_line = head.splitlines()[0].decode(errors="replace")
            result["http_status"] = int(status_line.split()[1])
        except Exception:  # noqa: BLE001
            result["http_status"] = None
        ok_json = False
        if token and payload:
            try:
                doc = json.loads(payload.decode(errors="replace"))
                ok_json = bool(doc.get("ok"))
                if ok_json:
                    uname = (doc.get("result") or {}).get("username", "?")
                    result["getme"] = True
                    print(f"[3/3] getMe por el túnel OK: bot=@{uname}", flush=True)
                    dbg("getme_ok", store, {"bot": uname, "http": result["http_status"]})
            except Exception:  # noqa: BLE001
                ok_json = False
        if not token:
            print(f"[3/3] GET / por el túnel OK: {result['http_status']}")
        elif not ok_json:
            print(f"[3/3] HTTP {result['http_status']} pero getMe sin ok:true; body: {payload[:120]!r}")
            raise RelayError(f"getMe falló (HTTP {result['http_status']})")
        result["ok"] = True
        result["total_ms"] = round((time.time() - t_total0) * 1000)
    except Exception as e:  # noqa: BLE001
        result["error"] = f"{type(e).__name__}: {e}"
        print(f"[FALLO] {result['error']}", flush=True)
        dbg("fallo", store, {"error": result["error"][:200]})
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass

    print(json.dumps({k: v for k, v in result.items() if k != "ok"} | {"ok": result["ok"]},
                     ensure_ascii=False, indent=None))

    # Publicar el resultado en el bucket (sobre firmado; legible por quien
    # tenga el secreto) para poder verificarlo desde fuera del runner.
    try:
        result_obj = dict(result)
        result_obj["ts"] = round(time.time())
        result_obj["iso"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        escrito = store.put("_v2_selftest_result.json", json.dumps(result_obj, ensure_ascii=False).encode())
        print(f"RESULTADO_GUARDADO={escrito}", flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"(escribir resultado al bucket falló: {e})", flush=True)

    if result["ok"]:
        msg = (f"Telegram Relay — SELFTEST E2E OK desde el runner: sesion relay {result['connect_ms']} ms, "
               f"handshake TLS por el tunel {result['tls_hs_ms']} ms"
               + (f", getMe del bot por el tunel OK (HTTP {result['http_status']})" if result.get("getme")
                  else f", HTTP {result['http_status']}") +
               f". Total {result.get('total_ms')} ms. El despliegue queda DEMOSTRADO.")
    else:
        msg = (f"Telegram Relay — SELFTEST E2E FALLO desde el runner: {result['error']}. "
               "Se reintentara en el proximo ciclo del relay.")
    notified = notify_direct(token, chat_id, msg)
    print(("notificado_al_grupo" if notified else "sin_notificacion") if (token and chat_id) else "sin_config_tg")
    sys.exit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
