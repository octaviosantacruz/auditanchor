package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/octaviosantacruz/auditanchor/internal/anchor"
	"github.com/octaviosantacruz/auditanchor/internal/eventlog"
	"github.com/octaviosantacruz/auditanchor/internal/merkle"
)

type Server struct {
	store  *eventlog.Store
	anchor *anchor.FileAnchor
}

type batchResponse struct {
	Count   int            `json:"count"`
	Root    string         `json:"root"`
	Receipt anchor.Receipt `json:"receipt"`
}

type proofResponse struct {
	Index int                `json:"index"`
	Root  string             `json:"root"`
	Event eventlog.Event     `json:"event"`
	Proof []merkle.ProofStep `json:"proof"`
}

func NewServer(store *eventlog.Store, anchor *anchor.FileAnchor) *Server {
	return &Server{store: store, anchor: anchor}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /events", s.appendEvent)
	mux.HandleFunc("POST /batches", s.anchorBatch)
	mux.HandleFunc("GET /proof/{index}", s.proof)
	return mux
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) appendEvent(w http.ResponseWriter, r *http.Request) {
	var event eventlog.Event
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&event); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if event.Source == "" || event.EventID == "" || event.Action == "" {
		writeError(w, http.StatusBadRequest, "source, event_id, and action are required")
		return
	}
	if err := s.store.Append(event); err != nil {
		writeError(w, http.StatusInternalServerError, "could not append event")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (s *Server) anchorBatch(w http.ResponseWriter, r *http.Request) {
	_, records, err := s.store.ReadAll()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read event log")
		return
	}
	tree := merkle.New(records)
	root := tree.RootHex()
	receipt, err := s.anchor.Anchor(root)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not anchor root")
		return
	}
	writeJSON(w, http.StatusCreated, batchResponse{Count: len(records), Root: root, Receipt: receipt})
}

func (s *Server) proof(w http.ResponseWriter, r *http.Request) {
	index, err := strconv.Atoi(r.PathValue("index"))
	if err != nil || index < 0 {
		writeError(w, http.StatusBadRequest, "invalid proof index")
		return
	}
	events, records, err := s.store.ReadAll()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read event log")
		return
	}
	if index >= len(records) {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}
	tree := merkle.New(records)
	writeJSON(w, http.StatusOK, proofResponse{Index: index, Root: tree.RootHex(), Event: events[index], Proof: tree.Proof(index)})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
