# AGENTS.md — AuditAnchor

AuditAnchor es una librería Go + CLI (no un servicio): árbol de Merkle RFC 6962
(`merkle/`), pruebas OpenTimestamps (`ots/`), recibos portables (`receipt/`) y
el CLI `cmd/auditanchor`. Lo importan Ozal, SIGEA y Custodia. Ver `README.md`,
`docs/design.md` y `STATUSCHECK.md`. Repo público, licencia MIT.

## Comandos

```sh
go test -race ./...
go vet ./...
go test ./merkle -run=^$ -fuzz=FuzzVerifyInclusion -fuzztime=30s
go test ./ots    -run=^$ -fuzz=FuzzParse           -fuzztime=30s
go run ./cmd/auditanchor -h
```

No tiene puerto ni datos persistentes propios. `stamp` y `upgrade` hablan con
los calendarios públicos de OpenTimestamps; los tests no usan la red.

## Infra local (server)

Bases, puertos y respaldos de este server: `/home/saint/projects/server-ops`
(`docs/INFRAESTRUCTURA.md`, `docs/DB.md`).

## Reglas

- Primitivas criptográficas sólo de la stdlib o `golang.org/x/crypto`; nunca
  implementadas a mano. Ver el skill `witness`.
- No romper: separación de dominio 0x00/0x01, split RFC 6962 sin duplicar
  nodos, head digest con tamaño, allowlist de `Upgrade`, límites del parser.
- Cambios en `ots/` deben seguir leyendo `testdata/hello-world.txt.ots` byte a
  byte idéntico y verificando contra el header real del bloque 358391.
- `x/crypto` fijado a la misma versión que Ozal para no forzarle upgrades.
- No commitear ni pushear sin pedido explícito.
- Nunca imprimir, copiar ni commitear secretos (`.env`, tokens, passwords).
