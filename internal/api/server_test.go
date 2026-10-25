package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/octaviosantacruz/auditanchor/internal/anchor"
	"github.com/octaviosantacruz/auditanchor/internal/eventlog"
)

func TestOversizedEventDoesNotBlockBatchOrProof(t *testing.T) {
	dir := t.TempDir()
	store, err := eventlog.NewStore(filepath.Join(dir, "events.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	fileAnchor, err := anchor.NewFileAnchor(filepath.Join(dir, "receipts.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(store, fileAnchor).Routes()

	validBody, err := json.Marshal(eventlog.Event{Source: "test", EventID: "valid", Action: "created"})
	if err != nil {
		t.Fatal(err)
	}
	validRequest := httptest.NewRequest(http.MethodPost, "/events", bytes.NewReader(validBody))
	validResponse := httptest.NewRecorder()
	handler.ServeHTTP(validResponse, validRequest)
	if validResponse.Code != http.StatusAccepted {
		t.Fatalf("valid event status = %d, want %d", validResponse.Code, http.StatusAccepted)
	}

	largeBody, err := json.Marshal(eventlog.Event{Source: "test", EventID: "large", Action: "created", Data: json.RawMessage(`{"payload":"` + strings.Repeat("x", 70*1024) + `"}`)})
	if err != nil {
		t.Fatal(err)
	}
	largeRequest := httptest.NewRequest(http.MethodPost, "/events", bytes.NewReader(largeBody))
	largeResponse := httptest.NewRecorder()
	handler.ServeHTTP(largeResponse, largeRequest)
	if largeResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized event status = %d, want %d", largeResponse.Code, http.StatusRequestEntityTooLarge)
	}

	batchRequest := httptest.NewRequest(http.MethodPost, "/batches", nil)
	batchResponse := httptest.NewRecorder()
	handler.ServeHTTP(batchResponse, batchRequest)
	if batchResponse.Code != http.StatusCreated {
		t.Fatalf("batch status = %d, want %d: %s", batchResponse.Code, http.StatusCreated, batchResponse.Body.String())
	}

	proofRequest := httptest.NewRequest(http.MethodGet, "/proof/0", nil)
	proofResponse := httptest.NewRecorder()
	handler.ServeHTTP(proofResponse, proofRequest)
	if proofResponse.Code != http.StatusOK {
		t.Fatalf("proof status = %d, want %d: %s", proofResponse.Code, http.StatusOK, proofResponse.Body.String())
	}
}
