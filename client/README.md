# Cliente de referencia (Python)

Implementación completa del protocolo **Telegram Relay v2** (túnel TCP sobre un
bucket S3/MinIO) lista para usar como base del transporte de la app Android
(portar a Kotlin) o para pruebas manuales.

## Archivos

- `relay_client.py` — biblioteca: `RelayStore` (HTTP + sobre TDS3) y
  `RelaySocket` (socket virtual TCP: connect / send / recv / shutdown_write / close).
- `selftest.py` — prueba E2E: abre sesión a `api.telegram.org:443` a través del
  bucket real, completa un handshake TLS, hace `GET /` y `getMe` del bot por el
  túnel, imprime latencias y notifica el resultado al grupo de Telegram
  (conexión directa).

## Protocolo (v2, cifrado)

Sobre TDS3 sobre TODA clave del bucket:

```
"TDS3" | HMAC-SHA256(secreto, clave || 0x00 || blob) 32B | blob
blob    = nonce(12) || AES-256-GCM(payload)
clave AES = HMAC-SHA256(secreto, "todus-relay-v1/encryption-key")
```

Trama TDV2 dentro del payload:

```
"TDV2" | ver=2 (u8) | seq (u64 BE) | len (u32 BE) | crc32 (u32 BE) | datos
```

Claves del bucket: `_v2_queue.txt` (+slots `_v2_queue_{1,2,3}.txt`),
`_v2_target_{id}.json`, `_v2_status_{id}.json`, `_v2_{c2s|s2c}_{id}_{seq:016d}.bin`,
`_v2_ack_{dir}_{id}.txt`, `_v2_fin_{dir}_{id}.txt`, `_v2_close_{id}.txt`.

## Uso

```python
from relay_client import RelayStore, RelaySocket

store = RelayStore("https://s3.todus.cu/public", SECRET_HEX)
sock = RelaySocket(store, chunk_size=512*1024, window=32, ack_every=8)
sock.connect("api.telegram.org", 443)
sock.send(b"GET / HTTP/1.1\r\nHost: api.telegram.org\r\nConnection: close\r\n\r\n")
sock.shutdown_write()
while (chunk := sock.recv(65536, timeout=10)) :
    ...
sock.close()
```

Para TLS usar `ssl.SSLContext.wrap_bio` (ver `selftest.py`), que funciona sobre
cualquier transporte sin hilos.

## Variables del selftest

```
RELAY_BASE_URL=https://s3.todus.cu/public
PROXY_SHARED_SECRET=<hex de 32+ bytes>
TG_BOT_TOKEN=<opcional, para getMe + notificar>
TG_GROUP_ID=<opcional, grupo a notificar>
```

Ejecutar: `python3 client/selftest.py` (requiere `pip install cryptography`).
