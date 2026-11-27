# telegram_relay_vps

Relay de túnel TCP/UDP sobre almacenamiento S3 para **Telegram**, escrito en Go 1.22 usando **solo la biblioteca estándar** (sin dependencias externas). Es el punto de salida (egress) del transporte de **Telegram Relay**: el cliente Android encapsula MTProto en peticiones S3 anónimas y este relay las reenvía a los datacenters de Telegram.

> Adaptación para Telegram del relay original: allowlist con soporte **CIDR** preconfigurada con los rangos de los DC de Telegram (`149.154.160.0/20`, `91.108.0.0/16`), renombrado de variables (`RELAY_BASE_URL` con compatibilidad `TODUS_BASE_URL`), defaults de **velocidad máxima** (poll 30 ms, ventana 32, chunks 512 KB, HTTP/2), y workflow de GitHub Actions con `ALLOWLIST_DEFAULT=telegram`.

## Arquitectura

```
Telegram Relay (APK) ──(HTTP PUT/GET/DELETE anónimo)──> Bucket S3
                                                            ▲
                                                            │ sondeo (poll)
                                                            │
                                                        Relay (este binario)
                                                            │
                                                            ▼ net.Dial TCP/UDP
                                                    DC de Telegram (MTProto)
                                  149.154.160.0/20 · 91.108.0.0/16 · api.telegram.org
```

- **Transporte encubierto**: todo se ve como peticiones S3 anónimas con `User-Agent: curl/8.23.0` (configurable vía `USER_AGENT`).
- **Protocolo**: frames `TDV2` (TCP), lotes `TDU2` (UDP), sobres `TDS2` (legacy HMAC) y `TDS3` (HMAC + AES-GCM cifrado).
- **Store-and-forward**: no hay conexión directa cliente↔relay; la coordinación es por convención de llaves `_v2_*` en el bucket.
- **TDLib no toca un proxy**: en el cliente, TDLib conecta a un servidor SOCKS5 embebido en `127.0.0.1` que implementa este protocolo; para TDLib es su conexión directa al servidor.

## Ficheros

| Fichero | Función |
| --- | --- |
| `main.go` | Worker, manejo de sesión TCP/UDP, shutdown graceful, heartbeat |
| `config.go` | `Settings`, carga desde `.env` / variables de entorno |
| `protocol.go` | Frames `TDV2`, lotes `TDU2`, helpers de llaves |
| `store.go` | Cliente HTTP S3 (HTTP/2), sobres `TDS2`/`TDS3`, backoff, métricas |
| `crypto.go` | Derivación de clave AES-256 y cifrado AES-GCM |
| `allowlist.go` | Filtro de destinos con soporte CIDR (anti open-proxy) |
| `logger.go` | `log/slog` JSON a stdout |
| `shutdown.go` | Captura SIGTERM/SIGINT → context cancel |

## Protocolo (referencia para implementar clientes)

Llaves en el bucket (prefijo `_v2_`):

| Llave | Dirección | Contenido |
| --- | --- | --- |
| `_v2_queue.txt` (o `_v2_queue_N.txt`, N=0..3) | c→s | IDs de sesión (uno por línea) |
| `_v2_target_{id}.json` | c→s | `{"version":2,"mode":"tcp"\|"udp","host":...,"port":...}` |
| `_v2_status_{id}.json` | s→c | `{"state":"ready"\|"closed"\|"error",...}` |
| `_v2_close_{id}.txt` | c→s | presencia = cerrar sesión |
| `_v2_{dir}_{id}_{seq:016d}.bin` | bidireccional | frame `TDV2` dentro de sobre `TDS2`/`TDS3` |
| `_v2_ack_{dir}_{id}.txt` | bidireccional | contador de frames recibidos |
| `_v2_fin_{dir}_{id}.txt` | bidireccional | contador de frames enviados (fin de stream) |

`dir` ∈ `c2s` (cliente→servidor) / `s2c` (servidor→cliente).

Frame `TDV2` (21 bytes de cabecera + payload):

```
"TDV2" | ver:1 | seq:u64BE | len:u32BE | crc32(payload):u32BE | payload
```

Sobre `TDS3` (cifrado, default):

```
"TDS3" | HMAC-SHA256(key || 0x00 || blob):32 | nonce(12) || AES-256-GCM(payload)
```

Sobre `TDS2` (legacy):

```
"TDS2" | HMAC-SHA256(key || 0x00 || payload):32 | payload
```

Clave AES: `HMAC-SHA256(secret, "todus-relay-v1/encryption-key")`.

Flujo TCP del cliente: PUT target → PUT queue (id) → esperar `status=ready` → PUT frames `c2s` (seq 0..) → poll GET frames `s2c` → PUT ack `c2s` periódicamente → `fin c2s` + `close` para terminar.

## Configuración

Copia `.env.example` a `.env` y rellena los valores, o define las variables de entorno directamente. Las variables críticas:

| Variable | Default | Descripción |
| --- | --- | --- |
| `PROXY_SHARED_SECRET` | (obligatorio) | Secreto HMAC + AES en hex, mínimo 32 bytes. `openssl rand -hex 32`. Debe coincidir con el del APK. |
| `RELAY_BASE_URL` | `https://s3.todus.cu/stickers` | URL del bucket (acepta `TODUS_BASE_URL` legacy) |
| `ENCRYPTION_ENABLED` | `true` | Cifrado AES-GCM del payload (sobre `TDS3`) |
| `ALLOWLIST` | (vacío) | Reglas `host:port` / `CIDR:port` separadas por coma. Vacío = permitir todo (warning) |
| `ALLOWLIST_DEFAULT` | (vacío) | `telegram` = si `ALLOWLIST` está vacío, restringir automáticamente a los DC de Telegram |
| `HEARTBEAT_INTERVAL` | `60` | Segundos entre logs de heartbeat |
| `SESSION_MAX_DURATION` | `14400` (4h) | Duración máxima por sesión |
| `SHUTDOWN_TIMEOUT` | `20` | Segundos de gracia tras SIGTERM |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `WRITE_TIMEOUT` | `15` | Timeout de escritura al destino TCP |

Tuning de velocidad (defaults para máxima velocidad): `POLL_INTERVAL=0.03`, `CHUNK_SIZE=524288`, `WINDOW_SIZE=32`, `ACK_EVERY=8`, `QUEUE_POLL_INTERVAL=0.15`.

## Desarrollo local

```bash
make vet          # go vet
make test         # go test
make race         # go test -race
make build        # genera ./telegram_relay_vps
./telegram_relay_vps # corre con .env en CWD
```

Requisitos: Go 1.22+.

## Despliegue en VPS (systemd)

```ini
# /etc/systemd/system/telegram-relay.service
[Unit]
Description=Telegram Relay VPS
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/opt/telegram_relay_vps
ExecStart=/opt/telegram_relay_vps/telegram_relay_vps
Restart=always
RestartSec=5
# Hardening básico
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/telegram_relay_vps

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now telegram-relay
journalctl -u telegram-relay -f
```

## Despliegue en Docker

```bash
docker build -t telegram_relay_vps .
docker run -d --restart=always \
  -e PROXY_SHARED_SECRET=<hex> \
  -e RELAY_BASE_URL=https://mi-bucket/prefijo \
  -e ALLOWLIST_DEFAULT=telegram \
  telegram_relay_vps
```

## Despliegue en GitHub Actions

El repo incluye dos workflows:

- `.github/workflows/ci.yml` — CI: `go vet`, `go test -race`, build en cada push/PR.
- `.github/workflows/relay.yml` — Ejecuta el relay en schedule (máx 6h/job, se relanza solo). Captura SIGTERM para shutdown graceful.

Secrets recomendados del repo: `PROXY_SHARED_SECRET`, `RELAY_BASE_URL`, `ALLOWLIST`, `GH_TOKEN`.

## Modelo de seguridad

- **Autenticación**: HMAC-SHA256 con clave de 32+ bytes, comparación de tiempo constante, binding de la llave al MAC (anti relocalización).
- **Cifrado**: AES-256-GCM con clave derivada del secreto. El payload es ilegible sin el secreto incluso con acceso de lectura al bucket.
- **Allowlist**: con `ALLOWLIST_DEFAULT=telegram` o `ALLOWLIST` explícito, solo se aceptan los DC de Telegram; el resto se rechaza con `status=error`.
- **TLS**: verificado por defecto (`InsecureSkipVerify` solo si `RELAY_VERIFY_TLS=false`).

## Compatibilidad con clientes legacy

Si `ENCRYPTION_ENABLED=true` (default), el relay **escribe** sobres `TDS3` (cifrados) pero **lee** tanto `TDS2` como `TDS3`.

## Licencia

Código del usuario. Ver repositorio original.
