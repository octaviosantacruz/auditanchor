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
