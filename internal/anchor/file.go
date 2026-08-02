package anchor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Receipt struct {
	Root      string    `json:"root"`
	Backend   string    `json:"backend"`
	Timestamp time.Time `json:"timestamp"`
	Reference string    `json:"reference"`
}

type FileAnchor struct {
	path string
	mu   sync.Mutex
}

func NewFileAnchor(path string) (*FileAnchor, error) {
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
	return &FileAnchor{path: path}, nil
}

func (a *FileAnchor) Anchor(root string) (Receipt, error) {
	receipt := Receipt{Root: root, Backend: "file", Timestamp: time.Now().UTC(), Reference: a.path}
	line, err := json.Marshal(receipt)
	if err != nil {
		return Receipt{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	file, err := os.OpenFile(a.path, os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return Receipt{}, err
	}
	defer file.Close()
	_, err = file.Write(append(line, '\n'))
	return receipt, err
}
