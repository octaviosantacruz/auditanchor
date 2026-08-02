package eventlog

import (
	"encoding/json"
	"time"
)

type Event struct {
	Timestamp time.Time       `json:"timestamp"`
	Source    string          `json:"source"`
	EventID   string          `json:"event_id"`
	Subject   string          `json:"subject"`
	Action    string          `json:"action"`
	Data      json.RawMessage `json:"data,omitempty"`
}

func (e Event) Canonical() ([]byte, error) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	} else {
		e.Timestamp = e.Timestamp.UTC()
	}
	return json.Marshal(e)
}
