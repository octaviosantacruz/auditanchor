package ots

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// BitcoinAttestation claims that the block at Height has MerkleRoot (internal
// byte order, as serialized in the header) in its header.
type BitcoinAttestation struct {
	Height     uint64
	MerkleRoot []byte
}

// ErrBitcoinMismatch means the block header does not contain the attested root.
var ErrBitcoinMismatch = errors.New("ots: block header does not match attestation")

// HeaderSize is the length of a serialized Bitcoin block header.
const HeaderSize = 80

// VerifyHeader checks the attestation against a raw 80-byte block header and
// returns the block time. The caller is responsible for the header being the
// one at a.Height on the best chain: that is the only trust assumption left.
func (a BitcoinAttestation) VerifyHeader(header []byte) (time.Time, error) {
	if len(header) != HeaderSize {
		return time.Time{}, fmt.Errorf("ots: block header is %d bytes, want %d", len(header), HeaderSize)
	}
	if len(a.MerkleRoot) != 32 {
		return time.Time{}, fmt.Errorf("%w: attested message is %d bytes, not a Merkle root", ErrBitcoinMismatch, len(a.MerkleRoot))
	}
	if !bytes.Equal(header[36:68], a.MerkleRoot) {
		return time.Time{}, fmt.Errorf("%w at height %d", ErrBitcoinMismatch, a.Height)
	}
	return time.Unix(int64(binary.LittleEndian.Uint32(header[68:72])), 0).UTC(), nil
}

// MerkleRootHex is the attested Merkle root in the byte order block explorers
// and "bitcoin-cli getblockheader" display (reversed).
func (a BitcoinAttestation) MerkleRootHex() string {
	r := make([]byte, len(a.MerkleRoot))
	for i, c := range a.MerkleRoot {
		r[len(r)-1-i] = c
	}
	return hex.EncodeToString(r)
}

// BlockHash returns the display-order hash of a raw block header.
func BlockHash(header []byte) string {
	first := sha256.Sum256(header)
	second := sha256.Sum256(first[:])
	for i, j := 0, len(second)-1; i < j; i, j = i+1, j-1 {
		second[i], second[j] = second[j], second[i]
	}
	return hex.EncodeToString(second[:])
}

// HeaderSource returns the raw header of the best-chain block at a height.
type HeaderSource interface {
	Header(ctx context.Context, height uint64) ([]byte, error)
}

// Esplora fetches headers from an Esplora HTTP API (blockstream.info/api,
// mempool.space/api or a self-hosted instance). Using a public instance means
// trusting it for the height-to-block mapping; run your own node to avoid that.
type Esplora struct {
	BaseURL string
	Client  *http.Client
}

// Header implements HeaderSource. It checks that the returned header hashes to
// the block hash the server reported for that height.
func (e Esplora) Header(ctx context.Context, height uint64) ([]byte, error) {
	base := strings.TrimRight(e.BaseURL, "/")
	hash, err := e.get(ctx, base+"/block-height/"+strconv.FormatUint(height, 10))
	if err != nil {
		return nil, err
	}
	hash = strings.TrimSpace(hash)
	if len(hash) != 64 {
		return nil, fmt.Errorf("ots: esplora returned an invalid block hash for height %d", height)
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return nil, fmt.Errorf("ots: esplora returned an invalid block hash for height %d", height)
	}
	hdrHex, err := e.get(ctx, base+"/block/"+hash+"/header")
	if err != nil {
		return nil, err
	}
	header, err := hex.DecodeString(strings.TrimSpace(hdrHex))
	if err != nil || len(header) != HeaderSize {
		return nil, fmt.Errorf("ots: esplora returned an invalid header for block %s", hash)
	}
	if BlockHash(header) != hash {
		return nil, fmt.Errorf("ots: esplora header does not hash to block %s", hash)
	}
	return header, nil
}

func (e Esplora) get(ctx context.Context, url string) (string, error) {
	client := e.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ots: %s returned %s", url, resp.Status)
	}
	return string(body), nil
}

// VerifyBitcoin checks every Bitcoin attestation of t against src and returns
// the earliest verified block time. It fails if t has no Bitcoin attestation
// or any of them does not match.
func VerifyBitcoin(ctx context.Context, t *Timestamp, src HeaderSource) (time.Time, uint64, error) {
	atts := t.Bitcoin()
	if len(atts) == 0 {
		return time.Time{}, 0, errors.New("ots: no Bitcoin attestation (still pending?)")
	}
	var best time.Time
	var bestHeight uint64
	for _, a := range atts {
		header, err := src.Header(ctx, a.Height)
		if err != nil {
			return time.Time{}, 0, err
		}
		when, err := a.VerifyHeader(header)
		if err != nil {
			return time.Time{}, 0, err
		}
		if best.IsZero() || when.Before(best) {
			best, bestHeight = when, a.Height
		}
	}
	return best, bestHeight, nil
}
