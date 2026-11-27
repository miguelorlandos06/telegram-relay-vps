#!/usr/bin/env python3
"""relay_client.py — Cliente de referencia del protocolo Telegram Relay v2.

Implementa el túnel TCP sobre un bucket S3 (transporte tipo MinIO) exactamente
como el servidor Go (telegram_relay_vps):

  Envelope TDS3 sobre TODA clave:
    "TDS3" | HMAC-SHA256(secreto, clave||0x00||blob) 32B | blob
    blob = nonce(12) || AES-256-GCM(payload)
    clave AES = HMAC-SHA256(secreto, "todus-relay-v1/encryption-key")

  Trama TDV2 dentro del payload:
    "TDV2" | ver=2 u8 | seq u64BE | len u32BE | crc32(IEEE) u32BE | datos

  Claves:
    _v2_queue.txt / _v2_queue_{1,2,3}.txt   -> líneas con ids de sesión
    _v2_target_{id}.json   {"version":2,"mode":"tcp","host":H,"port":P}
    _v2_status_{id}.json   {"state":"ready"|"error"|"closed",...}
    _v2_{c2s|s2c}_{id}_{seq:016d}.bin
    _v2_ack_{dir}_{id}.txt  (contador siguiente seq)
    _v2_fin_{dir}_{id}.txt  (total de tramas)
    _v2_close_{id}.txt

Uso:
    from relay_client import RelayStore, RelaySocket
    sock = RelaySocket(RelayStore(base_url, secret_hex))
    sock.connect("api.telegram.org", 443)
    sock.send(b"hola")
    data = sock.recv(65536, timeout=10)
    sock.close()

No usa hilos: recv() encuesta el bucket; para TLS usar wrap_bio() (ver selftest.py).
"""

import hashlib
import hmac
import json
import os
import secrets as pysecrets
import struct
import time
import zlib
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover
    AESGCM = None

ENVELOPE_MAGIC_SECURE = b"TDS3"
ENVELOPE_MAGIC_LEGACY = b"TDS2"
TAG_SIZE = 32
NONCE_SIZE = 12
KEY_INFO = b"todus-relay-v1/encryption-key"

FRAME_MAGIC = b"TDV2"
FRAME_VERSION = 2
FRAME_HEADER_SIZE = 21  # 4 + 1 + 8 + 4 + 4


class RelayError(Exception):
    """Error de protocolo o de transporte del relay."""


class RelayClosed(RelayError):
    """El par cerró el túnel (EOF limpio)."""


def derive_aes_key(secret: bytes) -> bytes:
    return hmac.new(secret, KEY_INFO, hashlib.sha256).digest()


def encode_frame(seq: int, payload: bytes) -> bytes:
    return (
        FRAME_MAGIC
        + struct.pack(">BQII", FRAME_VERSION, seq, len(payload), zlib.crc32(payload) & 0xFFFFFFFF)
        + payload
    )


def decode_frame(raw: bytes, expected_seq: int) -> bytes:
    if len(raw) < FRAME_HEADER_SIZE:
        raise RelayError(f"trama truncada ({len(raw)}B)")
    if raw[:4] != FRAME_MAGIC or raw[4] != FRAME_VERSION:
        raise RelayError("firma de trama incorrecta")
    seq = struct.unpack(">Q", raw[5:13])[0]
    length, crc = struct.unpack(">II", raw[13:21])
    if seq != expected_seq:
        raise RelayError(f"seq {seq} != esperado {expected_seq}")
    payload = raw[FRAME_HEADER_SIZE:]
    if len(payload) != length:
        raise RelayError(f"longitud {len(payload)} != {length}")
    if (zlib.crc32(payload) & 0xFFFFFFFF) != crc:
        raise RelayError("crc32 incorrecto")
    return payload


def data_key(direction: str, sid: str, seq: int) -> str:
    return f"_v2_{direction}_{sid}_{seq:016d}.bin"


def ack_key(direction: str, sid: str) -> str:
    return f"_v2_ack_{direction}_{sid}.txt"


def fin_key(direction: str, sid: str) -> str:
    return f"_v2_fin_{direction}_{sid}.txt"


def queue_key(slot: int) -> str:
    return "_v2_queue.txt" if slot <= 0 else f"_v2_queue_{slot}.txt"


class RelayStore:
    """Cliente HTTP del bucket con sobre autenticado (y cifrado) TDS3."""

    def __init__(self, base_url: str, secret_hex: str, user_agent: str = "curl/8.23.0",
                 http_timeout: float = 30.0, retries: int = 3, encryption: bool = True):
        self.base_url = base_url.rstrip("/")
        self.secret = bytes.fromhex(secret_hex) if isinstance(secret_hex, str) else secret_hex
        if len(self.secret) < 32:
            raise RelayError("el secreto debe ser >= 32 bytes")
        self.ua = user_agent
        self.http_timeout = http_timeout
        self.retries = retries
        self.encryption = encryption and AESGCM is not None
        self.aes_key = derive_aes_key(self.secret) if self.encryption else None
        self.gets = self.puts = self.deletes = 0
        self.put_errs = self.get_errs = 0

    # -- sobre TDS3 ----------------------------------------------------
    def _seal(self, key: str, data: bytes) -> bytes:
        blob = data
        magic = ENVELOPE_MAGIC_LEGACY
        if self.encryption:
            nonce = os.urandom(NONCE_SIZE)
            blob = nonce + AESGCM(self.aes_key).encrypt(nonce, data, None)
            magic = ENVELOPE_MAGIC_SECURE
        tag = hmac.new(self.secret, key.encode() + b"\x00" + blob, hashlib.sha256).digest()
        return magic + tag + blob

    def _open(self, key: str, envelope: bytes):
        if len(envelope) < 4 + TAG_SIZE:
            return None
        magic, tag, blob = envelope[:4], envelope[4:4 + TAG_SIZE], envelope[4 + TAG_SIZE:]
        if magic == ENVELOPE_MAGIC_LEGACY:
            pass
        elif magic == ENVELOPE_MAGIC_SECURE:
            if not self.encryption:
                return None
        else:
            return None
        expect = hmac.new(self.secret, key.encode() + b"\x00" + blob, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expect):
            return None
        if magic == ENVELOPE_MAGIC_SECURE:
            nonce, ct = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
            try:
                return AESGCM(self.aes_key).decrypt(nonce, ct, None)
            except Exception:
                return None
        return blob

    def _url(self, key: str) -> str:
        return self.base_url + "/" + "/".join(quote(p, safe="") for p in key.split("/"))

    # -- CRUD ----------------------------------------------------------
    def get(self, key: str, retries: int = None):
        """Devuelve el payload autenticado o None si ausente/inválido."""
        retries = self.retries if retries is None else retries
        for attempt in range(retries + 1):
            self.gets += 1
            try:
                req = Request(self._url(key), headers={"User-Agent": self.ua})
                with urlopen(req, timeout=self.http_timeout) as r:
                    if r.status != 200:
                        continue
                    return self._open(key, r.read())
            except HTTPError as e:
                if e.code == 404:
                    return None
                if e.code in (401, 403):
                    return None
                # 429/5xx: reintento
            except Exception:
                self.get_errs += 1
            time.sleep(0.05 * (attempt + 1))
        return None

    def put(self, key: str, data: bytes) -> bool:
        body = self._seal(key, data)
        for attempt in range(self.retries + 1):
            self.puts += 1
            try:
                req = Request(self._url(key), data=body, method="PUT",
                              headers={"User-Agent": self.ua,
                                       "Content-Type": "application/octet-stream"})
                with urlopen(req, timeout=self.http_timeout) as r:
                    if 200 <= r.status < 300:
                        return True
            except Exception:
                self.put_errs += 1
            time.sleep(0.1 * (attempt + 1))
        return False

    def delete(self, key: str) -> bool:
        self.deletes += 1
        try:
            req = Request(self._url(key), method="DELETE", headers={"User-Agent": self.ua})
            with urlopen(req, timeout=self.http_timeout) as r:
                return r.status in (200, 202, 204, 404)
        except HTTPError as e:
            return e.code == 404
        except Exception:
            return False


class RelaySocket:
    """Socket TCP virtual sobre el bucket (protocolo v2, sin hilos)."""

    def __init__(self, store: RelayStore, session_id: str = None, chunk_size: int = 524288,
                 window: int = 32, ack_every: int = 8, poll_interval: float = 0.025,
                 control_poll_interval: float = 0.05):
        self.store = store
        self.id = session_id or pysecrets.token_hex(8)
        self.chunk = chunk_size
        self.window = window
        self.ack_every = ack_every
        self.poll = poll_interval
        self.control_poll = control_poll_interval
        self.connected = False
        self.send_seq = 0
        self.recv_seq = 0
        self.c2s_ack = 0
        self.recv_buf = b""
        self.since_ack = 0
        self.last_ack_time = time.time()
        self.remote_closed = False
        self.write_shutdown = False
        self._closed = False

    # -- claves de esta sesión ------------------------------------------
    @property
    def target_key(self): return f"_v2_target_{self.id}.json"

    @property
    def status_key(self): return f"_v2_status_{self.id}.json"

    @property
    def close_key(self): return f"_v2_close_{self.id}.txt"

    # -- ciclo de vida ---------------------------------------------------
    def connect(self, host: str, port: int, timeout: float = 30.0):
        """Publica target, entra en la cola y espera state=ready."""
        if self.connected:
            raise RelayError("ya conectado")
        target = json.dumps({"version": 2, "mode": "tcp", "host": host, "port": port}).encode()
        if not self.store.put(self.target_key, target):
            raise RelayError("PUT target falló")
        self._enqueue()
        deadline = time.time() + timeout
        while time.time() < deadline:
            raw = self.store.get(self.status_key)
            if raw:
                try:
                    st = json.loads(raw.decode())
                except Exception:
                    st = {}
                state = st.get("state")
                if state == "ready":
                    self.connected = True
                    return
                if state == "error":
                    self._cleanup()
                    raise RelayError(f"relay rechazó la sesión: {st.get('message', '?')}")
            time.sleep(self.control_poll)
        self._cleanup()
        raise RelayError(f"timeout esperando ready (relay ¿corriendo?) host={host}:{port}")

    def _enqueue(self):
        slot = pysecrets.randbelow(4)  # 0..3 (0 = _v2_queue.txt)
        key = queue_key(slot)
        current = self.store.get(key) or b""
        ids = [ln.strip() for ln in current.decode(errors="replace").splitlines() if ln.strip()]
        if self.id in ids:
            return
        blob = ("\n".join(ids + [self.id]) + "\n").encode()
        if not self.store.put(key, blob):
            # reintento en el slot principal
            if key != queue_key(0):
                cur = self.store.get(queue_key(0)) or b""
                ids = [ln.strip() for ln in cur.decode(errors="replace").splitlines() if ln.strip()]
                self.store.put(queue_key(0), ("\n".join(ids + [self.id]) + "\n").encode())

    def _dequeue(self):
        for slot in range(4):
            key = queue_key(slot)
            current = self.store.get(key)
            if not current:
                continue
            ids = [ln.strip() for ln in current.decode(errors="replace").splitlines() if ln.strip()]
            if self.id not in ids:
                continue
            rest = [i for i in ids if i != self.id]
            blob = ("\n".join(rest) + "\n").encode() if rest else b""
            self.store.put(key, blob)

    # -- datos -----------------------------------------------------------
    def send(self, data: bytes):
        """Envía datos al destino (trocea, enmarca, respeta ventana+acks)."""
        if not self.connected:
            raise RelayError("no conectado")
        if self.write_shutdown:
            raise RelayError("escritura ya cerrada")
        off = 0
        while off < len(data):
            while self.send_seq - self.c2s_ack >= self.window:
                self._refresh_c2s_ack()
                if self.store.get(self.close_key) is not None:
                    raise RelayClosed("close recibido durante send")
                time.sleep(self.poll)
            piece = data[off:off + self.chunk]
            if not self.store.put(data_key("c2s", self.id, self.send_seq),
                                  encode_frame(self.send_seq, piece)):
                raise RelayError(f"PUT frame c2s {self.send_seq} falló")
            self.send_seq += 1
            off += len(piece)

    def _refresh_c2s_ack(self):
        raw = self.store.get(ack_key("c2s", self.id))
        if raw:
            try:
                val = int(raw.decode().strip() or "0")
            except ValueError:
                return
            if val > self.c2s_ack:
                self.c2s_ack = val

    def shutdown_write(self):
        """Indica fin del flujo c2s (el servidor hará CloseWrite al destino)."""
        if not self.write_shutdown:
            self.store.put(fin_key("c2s", self.id), str(self.send_seq).encode())
            self.write_shutdown = True

    def recv(self, max_bytes: int = 65536, timeout: float = None) -> bytes:
        """Lee hasta max_bytes del destino. b"" = EOF (par cerró)."""
        if self._closed:
            raise RelayError("socket cerrado")
        deadline = None if timeout is None else time.time() + timeout
        while not self.recv_buf:
            raw = self.store.get(data_key("s2c", self.id, self.recv_seq))
            if raw is not None:
                payload = decode_frame(raw, self.recv_seq)
                self.store.delete(data_key("s2c", self.id, self.recv_seq))
                self.recv_seq += 1
                self.since_ack += 1
                if self.since_ack >= self.ack_every or time.time() - self.last_ack_time > 5.0:
                    self.store.put(ack_key("s2c", self.id), str(self.recv_seq).encode())
                    self.since_ack = 0
                    self.last_ack_time = time.time()
                if payload:
                    self.recv_buf += payload
                    continue
            # sin dato: ¿fin remoto?
            fin = self.store.get(fin_key("s2c", self.id))
            if fin is not None:
                try:
                    total = int(fin.decode().strip() or "0")
                except ValueError:
                    total = 0
                if self.recv_seq >= total:
                    self.remote_closed = True
                    if self.since_ack:
                        self.store.put(ack_key("s2c", self.id), str(self.recv_seq).encode())
                        self.since_ack = 0
                    if not self.recv_buf:
                        return b""
            if deadline is not None and time.time() >= deadline:
                raise TimeoutError("recv: timeout sin datos")
            time.sleep(self.poll)
        out = self.recv_buf[:max_bytes]
        self.recv_buf = self.recv_buf[max_bytes:]
        return out

    # -- cierre ----------------------------------------------------------
    def close(self, drain_timeout: float = 8.0):
        """Fin c2s, espera drenaje, publica close y limpia todas las claves."""
        if self._closed:
            return
        try:
            if not self.write_shutdown:
                self.shutdown_write()
            deadline = time.time() + drain_timeout
            while time.time() < deadline:
                self._refresh_c2s_ack()
                if self.c2s_ack >= self.send_seq:
                    break
                time.sleep(self.poll)
            self.store.put(self.close_key, b"done")
        finally:
            self._closed = True
            self._cleanup()

    def _cleanup(self):
        s = self.store
        keys = [self.target_key, self.status_key, self.close_key,
                ack_key("c2s", self.id), ack_key("s2c", self.id),
                fin_key("c2s", self.id), fin_key("s2c", self.id)]
        for seq in range(self.send_seq):
            keys.append(data_key("c2s", self.id, seq))
        top = self.recv_seq
        fin = s.get(fin_key("s2c", self.id))
        if fin:
            try:
                top = max(top, int(fin.decode().strip() or "0"))
            except ValueError:
                pass
        for seq in range(top):
            keys.append(data_key("s2c", self.id, seq))
        for k in keys:
            s.delete(k)
        self._dequeue()


if __name__ == "__main__":
    import sys
    base = os.environ.get("RELAY_BASE_URL", "https://s3.todus.cu/public")
    secret = os.environ.get("PROXY_SHARED_SECRET", "")
    if not secret:
        print("define PROXY_SHARED_SECRET (hex)")
        sys.exit(2)
    store = RelayStore(base, secret)
    sock = RelaySocket(store)
    sock.connect("api.telegram.org", 443, timeout=30.0)
    try:
        sock.send(b"GET / HTTP/1.1\r\nHost: api.telegram.org\r\n"
                  b"User-Agent: curl/8.23.0\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        sock.shutdown_write()
        body = b""
        while True:
            try:
                chunk = sock.recv(65536, timeout=10.0)
            except TimeoutError:
                break
            if not chunk:
                break
            body += chunk
        print(body[:200].decode(errors="replace"))
    finally:
        sock.close()
