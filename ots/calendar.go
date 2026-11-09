package ots

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	userAgent        = "auditanchor"
	acceptHeader     = "application/vnd.opentimestamps.v1"
	maxResponseBytes = 10000
)

// DefaultCalendars are the public aggregation servers that accept submissions.
var DefaultCalendars = []string{
	"https://a.pool.opentimestamps.org",
	"https://b.pool.opentimestamps.org",
	"https://a.pool.eternitywall.com",
	"https://ots.btc.catallaxy.com",
}

// DefaultUpgradeAllowlist are the calendars Upgrade will contact. A pending
// attestation names a URL; following arbitrary URLs from an untrusted proof
// would let it make this process issue requests anywhere (SSRF), so only
// these patterns are honoured. "*" matches one DNS label.
var DefaultUpgradeAllowlist = []string{
	"https://*.btc.calendar.opentimestamps.org", // alice, bob, finney...
	"https://*.calendar.opentimestamps.org",
	"https://*.calendar.eternitywall.com",
	"https://*.calendar.catallaxy.com",
	"https://*.btc.catallaxy.com",
}

// Client talks to OpenTimestamps calendar servers.
type Client struct {
	HTTP      *http.Client // nil means a client with a 30 s timeout
	Calendars []string     // submission servers; nil means DefaultCalendars
	Allowlist []string     // upgrade servers; nil means DefaultUpgradeAllowlist
	// MinResponses is how many calendars must accept a submission (default 2,
	// or 1 if fewer calendars are configured).
	MinResponses int
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// Stamp submits digest to the calendars and returns a timestamp rooted at it,
// with one pending attestation per calendar that answered. A random 16-byte
// nonce is appended before hashing, as the reference client does, so the
// calendars never see the digest itself.
func (c *Client) Stamp(ctx context.Context, digest []byte) (*Timestamp, error) {
	cals := c.Calendars
	if cals == nil {
		cals = DefaultCalendars
	}
	min := c.MinResponses
	if min <= 0 {
		min = 2
	}
	if min > len(cals) {
		min = len(cals)
	}
	if min == 0 {
		return nil, errors.New("ots: no calendars configured")
	}

	root := New(digest)
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	n1, err := root.Add(Append(nonce))
	if err != nil {
		return nil, err
	}
	commit, err := n1.Add(SHA256())
	if err != nil {
		return nil, err
	}

	type result struct {
		cal string
		ts  *Timestamp
		err error
	}
	results := make(chan result, len(cals))
	for _, cal := range cals {
		go func(cal string) {
			ts, err := c.submit(ctx, cal, commit.Msg)
			results <- result{cal, ts, err}
		}(cal)
	}
	var errs []error
	ok := 0
	for range cals {
		r := <-results
		if r.err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.cal, r.err))
			continue
		}
		if err := commit.Merge(r.ts); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.cal, err))
			continue
		}
		ok++
	}
	if ok < min {
		return nil, fmt.Errorf("ots: only %d of %d required calendars answered: %w", ok, min, errors.Join(errs...))
	}
	return root, nil
}

func (c *Client) submit(ctx context.Context, cal string, msg []byte) (*Timestamp, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(cal, "/")+"/digest", bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	body, status, err := c.do(req)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("calendar returned HTTP %d", status)
	}
	return Parse(msg, body)
}

func (c *Client) do(req *http.Request) ([]byte, int, error) {
	req.Header.Set("Accept", acceptHeader)
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, 0, err
	}
	if len(body) > maxResponseBytes {
		return nil, 0, fmt.Errorf("calendar response exceeds %d bytes", maxResponseBytes)
	}
	return body, resp.StatusCode, nil
}

// UpgradeResult reports what Upgrade did.
type UpgradeResult struct {
	Upgraded []string // calendars that returned a completed proof
	Pending  []string // calendars that have not reached Bitcoin yet
	Skipped  []string // calendars not in the allowlist
	Errors   []error
}

// Upgrade asks each allowed calendar named by a pending attestation for the
// completed proof and merges it into t. A calendar that has not confirmed yet
// is reported as pending, not as an error. Pending attestations are kept: the
// reference client keeps them too, and they are harmless once a Bitcoin
// attestation exists.
func (c *Client) Upgrade(ctx context.Context, t *Timestamp) UpgradeResult {
	allow := c.Allowlist
	if allow == nil {
		allow = DefaultUpgradeAllowlist
	}
	var res UpgradeResult
	type job struct {
		node *Timestamp
		uri  string
	}
	var jobs []job
	t.walk(func(n *Timestamp) {
		for _, a := range n.Attestations {
			if uri, ok := a.PendingURI(); ok {
				jobs = append(jobs, job{n, uri})
			}
		}
	})
	for _, j := range jobs {
		if !allowed(j.uri, allow) {
			res.Skipped = append(res.Skipped, j.uri)
			continue
		}
		url := strings.TrimRight(j.uri, "/") + "/timestamp/" + hex.EncodeToString(j.node.Msg)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			res.Errors = append(res.Errors, err)
			continue
		}
		body, status, err := c.do(req)
		switch {
		case err != nil:
			res.Errors = append(res.Errors, fmt.Errorf("%s: %w", j.uri, err))
		case status == http.StatusNotFound:
			res.Pending = append(res.Pending, j.uri)
		case status != http.StatusOK:
			res.Errors = append(res.Errors, fmt.Errorf("%s: HTTP %d", j.uri, status))
		default:
			up, err := Parse(j.node.Msg, body)
			if err == nil {
				err = j.node.Merge(up)
			}
			if err != nil {
				res.Errors = append(res.Errors, fmt.Errorf("%s: %w", j.uri, err))
				continue
			}
			res.Upgraded = append(res.Upgraded, j.uri)
		}
	}
	return res
}

func allowed(uri string, patterns []string) bool {
	for _, p := range patterns {
		if !strings.Contains(p, "*") && strings.TrimRight(p, "/") == strings.TrimRight(uri, "/") {
			return true // exact entry, e.g. a self-hosted calendar
		}
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return false
	}
	if u.Path != "" && u.Path != "/" {
		return false
	}
	for _, p := range patterns {
		pu, err := url.Parse(strings.Replace(p, "*", "x", 1))
		if err != nil || pu.Scheme != u.Scheme {
			continue
		}
		host := strings.TrimPrefix(p, pu.Scheme+"://")
		if hostMatch(host, u.Hostname()) {
			return true
		}
	}
	return false
}

func hostMatch(pattern, host string) bool {
	pl := strings.Split(strings.ToLower(pattern), ".")
	hl := strings.Split(strings.ToLower(host), ".")
	if len(pl) != len(hl) {
		return false
	}
	for i := range pl {
		if pl[i] == "*" {
			if hl[i] == "" {
				return false
			}
			continue
		}
		if pl[i] != hl[i] {
			return false
		}
	}
	return true
}
