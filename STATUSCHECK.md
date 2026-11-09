# STATUSCHECK.md — AuditAnchor

_Auditoría: 2026-09-21 — actualizado 2026-09-21 (migrado de Docker a Go nativo)_

## Qué es
Servicio de anclaje de logs de auditoría a prueba de manipulación, en Go. Recibe eventos, los guarda como NDJSON, arma un árbol de Merkle y ancla el root vía un backend plugueable (hoy: receipts locales; a futuro: OpenTimestamps, Ethereum/Polygon testnet). Pensado para consumir eventos de MagicLink (`created`, `viewed`, etc.), pero es un proyecto genérico e independiente.

## Estado actual
- **Corre nativo con Go 1.26** (ya instalado en la máquina) — se sacó de Docker. `go build ./cmd/server` compila limpio, se corre directo el binario apuntando a `./data/*.ndjson`.
- Puerto `:8081`. `GET /healthz` → `{"status":"ok"}`. `POST /events` responde y valida payload (`source`, `event_id`, `action` requeridos).
- **Sin base de datos**: persiste todo en NDJSON en `./data/` (gitignoreado), no usa PostgreSQL.
- **Repositorio**: `git@github.com:octaviosantacruz/auditanchor.git`, privado, sin cambios de código (solo se dejó de depender de Docker para correrlo).

## Hallazgo resuelto
- El problema de permisos de esta auditoría (`permission denied` al escribir `/data/events.ndjson` dentro del contenedor `nonroot`) **desapareció al pasar a nativo** — ya no aplica, no hace falta resolverlo dentro de la imagen Docker a menos que se vuelva a necesitar Docker para producción/despliegue.

## Pendientes / próximos pasos
- Si en algún momento se despliega en un servidor real, `docker-compose.yml` sigue ahí y sirve, pero recordar el fix de permisos del volumen si se retoma ese camino (ver historial de este archivo / commits).
- No se probó el flujo completo de anclaje de Merkle root (`POST /batches`, `GET /proof/{index}`) más allá de los endpoints básicos.

## Dirección — 2026-11-09

**Decisión: no se archiva; se reposiciona.** AuditAnchor deja de ser un servicio
genérico de anclaje o un proyecto "blockchain" y pasa a ser la **capa de
integridad compartida** del portafolio: librería + CLI de verificación (+ servicio
opcional) que permite a un tercero comprobar que un registro existía en un momento
dado y no fue reescrito.

### Por qué así
- Como servicio genérico compite con Sigstore Rekor/Trillian, immudb u
  OpenTimestamps directo, sin diferencial claro.
- Anclar un hash en Bitcoin es criptografía aplicada (Merkle, pruebas de
  inclusión, sellos de tiempo), no desarrollo blockchain.
- Los tres proyectos principales prometen evidencia y les falta lo mismo:
  - **Ozal**: `internal/audit` ya encadena por hash y firma checkpoints Ed25519,
    pero su propio código reconoce que no prueban nada sin retenerlos fuera del
    host (`checkpoint.go`, `TamperEvident=false`).
  - **SIGEA**: "evidencia detrás de cada vulnerabilidad" → evidencia fechada e
    inalterable.
  - **Custodia**: conclusiones de correlación con prueba de integridad.

### Estado real del código (2026-11-09)
- `internal/merkle`: árbol SHA-256 con separación de dominio 0x00/0x01 (bien),
  pruebas de inclusión y `Verify`. **Sin tests.**
- **Fallo:** con nivel impar duplica el último nodo (estilo Bitcoin,
  CVE-2012-2459): `[a,b,c]` y `[a,b,c,c]` dan el mismo root. Cambiar a RFC 6962
  (promover el nodo sin pareja).
- `internal/anchor`: sólo backend de archivo local; no hay anclaje externo.
- README todavía se presenta como complemento de MagicLink (archivado 2026-11-09).

### Hito 1 — valida la idea (prioridad baja: después de la identidad Ozal↔Custodia)
1. Árbol RFC 6962 + tests de raíz/pruebas (vectores conocidos) + fuzz de
   `Proof`/`Verify`.
2. `auditanchor verify`: verificación offline que no confía en el servidor.
3. Backend OpenTimestamps (ancla en Bitcoin, sin wallet ni gas) y anclar un
   checkpoint real de Ozal; verificarlo desde otra máquina.

**Criterio de salida:** si el hito sale y la verificación por un tercero
convence, seguir con Ozal como primer consumidor y luego SIGEA. Si no, archivar
con esa evidencia.

### Forma: librería Go + CLI, repo público — 2026-11-09
- **Paquete, no servicio.** Ozal, SIGEA y Custodia importan el módulo; cada uno
  arma árboles sobre sus registros y guarda los recibos junto a sus datos. Sin
  proceso, puerto, disco ni respaldo extra.
- Destino: `merkle/` (RFC 6962), `ots/` (Stamp/Upgrade OpenTimestamps), `proof/`
  (recibo portable), `cmd/auditanchor verify`. Cada consumidor llama `Upgrade`
  desde su propio scheduler (los sellos OTS se confirman horas después).
- A retirar en el Hito 1: `cmd/server`, `internal/api`, `internal/eventlog`,
  `internal/anchor` (y Dockerfile/compose). Sólo `internal/merkle` sobrevive.
  Al retirar el servidor, quitar la reserva 8081 de `server-ops/ports.json` y la
  copia de `auditanchor/data` en `server-ops/internal/backup`.
- **Repo público** desde 2026-11-09: Ozal y Custodia son públicos y no pueden
  depender de un módulo privado; además el verificador "sin confiar en el
  servidor" exige código auditable. Historial revisado antes de publicar: sin
  secretos. Falta elegir licencia.

## Librería implementada — 2026-11-09

Hito 1, pasos 1 y 2 hechos; el 3 a medias (falta el checkpoint real de Ozal).

- **Servidor retirado**: `cmd/server`, `internal/*`, Dockerfile y compose
  borrados. Ya no hay puerto 8081 ni `data/`.
- **`merkle/`**: RFC 6962/9162 (raíz, inclusión, consistencia). Vectores de
  Certificate Transparency, exhaustivo 1–70 contra referencia ingenua, 3 fuzz.
  El fallo de duplicación (CVE-2012-2459) quedó corregido con test de regresión.
- **Hallazgo de diseño**: una ruta de inclusión no fija el tamaño del árbol
  (la misma ruta vale para tamaño 3 y 4 con la misma raíz). Por eso se ancla un
  head digest con dominio + tamaño + raíz (`receipt.HeadDigest`).
- **`ots/`**: formato OpenTimestamps completo (ops, atestaciones, archivo
  `.ots`), `Stamp` a varios calendarios con nonce, `Upgrade` con allowlist
  anti-SSRF, verificación contra header de bloque y fuente Esplora. Lee
  `hello-world.txt.ots` y lo re-serializa idéntico; verificado contra el header
  real del bloque 358391. `FuzzParse`: ~5M ejecuciones limpias.
- **`receipt/`**: recibo JSON estricto con anclas; `Verify` online u offline.
- **CLI** `auditanchor`: root, prove, stamp, upgrade, verify, info, export-ots.
- **Prueba real**: stamp de un log de demo contra los 4 calendarios públicos
  (alice, bob, finney, catallaxy): los 4 respondieron, `upgrade` informa
  pendiente. Guardado en `testdata/demo/receipt-pending.json`.
- Dependencia: `golang.org/x/crypto v0.57.0` (misma que Ozal) por RIPEMD-160 y
  Keccak de pruebas antiguas. Go 1.26 (igual que Ozal, Custodia y SIGEA).

### Pendiente
- Upgrade del recibo de demo cuando Bitcoin confirme (horas) y verificar con
  `-esplora` y con un nodo propio; guardar el recibo confirmado como fixture.
- Paso 3 del Hito 1: anclar un checkpoint real de Ozal y verificarlo desde
  otra máquina.
- Limpieza en server-ops: reserva 8081 retirada de `ports.json`; la copia de
  `auditanchor/data` en `internal/backup` queda inofensiva (el directorio no
  existe) hasta el próximo cambio en ese paquete.
