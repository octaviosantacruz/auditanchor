package eventlog

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

const maxRecordBytes = 60 * 1024

var ErrRecordTooLarge = errors.New("event record too large")

type Store struct {
	path string
	mu   sync.Mutex
}

func NewStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return &Store{path: path}, nil
}

func (s *Store) Append(event Event) error {
	record, err := event.Canonical()
	if err != nil {
		return err
	}
	if len(record)+1 > maxRecordBytes {
		return ErrRecordTooLarge
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	file, err := os.OpenFile(s.path, os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(append(record, '\n'))
	return err
}

func (s *Store) ReadAll() ([]Event, [][]byte, error) {
	file, err := os.Open(s.path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	var events []Event
	var records [][]byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		var event Event
		if err := json.Unmarshal(line, &event); err != nil {
			return nil, nil, err
		}
		events = append(events, event)
		records = append(records, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return events, records, nil
}
