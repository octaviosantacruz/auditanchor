package main

import (
	"log"
	"net/http"
	"os"

	"github.com/octaviosantacruz/auditanchor/internal/anchor"
	"github.com/octaviosantacruz/auditanchor/internal/api"
	"github.com/octaviosantacruz/auditanchor/internal/eventlog"
)

func main() {
	addr := env("AUDITANCHOR_ADDR", ":8081")
	logPath := env("AUDITANCHOR_LOG_PATH", "./data/events.ndjson")
	receiptsPath := env("AUDITANCHOR_RECEIPTS_PATH", "./data/receipts.ndjson")

	store, err := eventlog.NewStore(logPath)
	if err != nil {
		log.Fatalf("event store: %v", err)
	}
	fileAnchor, err := anchor.NewFileAnchor(receiptsPath)
	if err != nil {
		log.Fatalf("anchor store: %v", err)
	}

	server := api.NewServer(store, fileAnchor)
	log.Printf("auditanchor listening on %s", addr)
	if err := http.ListenAndServe(addr, server.Routes()); err != nil {
		log.Fatal(err)
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
