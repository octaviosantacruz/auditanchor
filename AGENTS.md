# AGENTS.md — AuditAnchor

AuditAnchor es el servicio local de auditoría (Go). Los eventos viven en
archivos NDJSON bajo `data/`. Ver `README.md` y `STATUSCHECK.md`.

## Comandos

```sh
go build ./...
go test ./...
go run ./cmd/server
```

Puerto registrado: `8081`.

## Infra local (server)

Bases, puertos y respaldos de este server: `/home/saint/projects/server-ops`
(`docs/INFRAESTRUCTURA.md`, `docs/DB.md`). El estado de git de todos los
proyectos se genera con `server-ops/bin/git-report` → `server-ops/docs/GIT.md`.

## Reglas

- Los NDJSON de `data/` son datos de auditoría: no editarlos a mano.
- No commitear ni pushear sin pedido explícito.
- Nunca imprimir, copiar ni commitear secretos (`.env`, tokens, passwords).
- Antes de commitear, revisar `server-ops/docs/GIT.md`.
