// Package api is the Vorynex Cloud ingestion API: the control-plane entry point
// for host enrollment, telemetry, and workload protection mode. It is
// deliberately out of the application's request path — a cloud outage must not
// affect enforcement.
package api

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vorynex/vorynex/engine/telemetry"
)

// Host is an enrolled agent.
type Host struct {
	ID           string    `json:"host_id"`
	Hostname     string    `json:"hostname"`
	Mode         string    `json:"mode"` // observe | protect | lockdown
	RegisteredAt time.Time `json:"registered_at"`
}

// StoredEvent is one ingested telemetry record.
type StoredEvent struct {
	Host   string           `json:"host_id"`
	Record telemetry.Record `json:"record"`
}

// Modes are the valid protection modes.
var Modes = map[string]bool{"observe": true, "protect": true, "lockdown": true}

// Store persists enrolled hosts and ingested events. It uses JSONL files so the
// MVP has no database dependency; a real store replaces it later.
type Store struct {
	mu    sync.Mutex
	path  string
	hosts map[string]Host
}

// NewStore opens (creating if needed) a store at path.
func NewStore(path string) *Store {
	st := &Store{path: path, hosts: map[string]Host{}}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	if f, err := os.Open(path + ".hosts"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if len(sc.Bytes()) == 0 {
				continue
			}
			var h Host
			if json.Unmarshal(sc.Bytes(), &h) == nil && h.ID != "" {
				st.hosts[h.ID] = h
			}
		}
		f.Close()
	}
	return st
}

// RegisterHost records an enrolled host, preserving an existing mode. New hosts
// start in observe mode (the documented, safe first step).
func (st *Store) RegisterHost(id, hostname string) Host {
	st.mu.Lock()
	defer st.mu.Unlock()
	h, ok := st.hosts[id]
	if !ok {
		h = Host{ID: id, Hostname: hostname, Mode: "observe", RegisteredAt: time.Now().UTC()}
	} else if hostname != "" {
		h.Hostname = hostname
	}
	st.hosts[id] = h
	st.saveHostsLocked()
	return h
}

// SetMode updates a host's protection mode. It reports whether the host exists.
func (st *Store) SetMode(id, mode string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	h, ok := st.hosts[id]
	if !ok {
		return false
	}
	h.Mode = mode
	st.hosts[id] = h
	st.saveHostsLocked()
	return true
}

// Hosts returns the enrolled hosts sorted by id.
func (st *Store) Hosts() []Host {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]Host, 0, len(st.hosts))
	for _, h := range st.hosts {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (st *Store) saveHostsLocked() {
	f, err := os.Create(st.path + ".hosts")
	if err != nil {
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, h := range st.hosts {
		b, _ := json.Marshal(h)
		w.Write(append(b, '\n'))
	}
	w.Flush()
}

// AppendRecords stores a batch of records for a host and returns the count.
func (st *Store) AppendRecords(hostID string, records []telemetry.Record) (int, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	f, err := os.OpenFile(st.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	for _, r := range records {
		b, err := json.Marshal(StoredEvent{Host: hostID, Record: r})
		if err != nil {
			return n, err
		}
		if _, err := f.Write(append(b, '\n')); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// Read returns ingested events, newest first, optionally filtered by host.
func (st *Store) Read(hostID string, limit int) ([]StoredEvent, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	f, err := os.Open(st.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []StoredEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 8*1024), 4<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e StoredEvent
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		if hostID != "" && e.Host != hostID {
			continue
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Record.Seq > out[j].Record.Seq })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Server is the cloud HTTP API.
type Server struct {
	token string
	store *Store
	mux   *http.ServeMux
}

// New builds a Server with the given bearer token (empty disables auth).
func New(token string, store *Store) *Server {
	s := &Server{token: token, store: store, mux: http.NewServeMux()}
	s.mux.HandleFunc("/v1/enroll", s.handleEnroll)
	s.mux.HandleFunc("/v1/events", s.handleEvents)
	s.mux.HandleFunc("/v1/hosts", s.handleHosts)
	s.mux.HandleFunc("/v1/hosts/", s.handleHost)
	return s
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) authorized(r *http.Request) bool {
	if s.token == "" {
		return true
	}
	return r.Header.Get("Authorization") == "Bearer "+s.token
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	if !s.authorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req struct {
		HostID   string `json:"host_id"`
		Hostname string `json:"hostname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.HostID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host_id required"})
		return
	}
	h := s.store.RegisterHost(req.HostID, req.Hostname)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "host": h})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		limit := 100
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		events, err := s.store.Read(r.URL.Query().Get("host_id"), limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"events": events})
	case http.MethodPost:
		var req struct {
			HostID  string             `json:"host_id"`
			Records []telemetry.Record `json:"records"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.HostID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host_id and records required"})
			return
		}
		s.store.RegisterHost(req.HostID, "")
		accepted, err := s.store.AppendRecords(req.HostID, req.Records)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"accepted": accepted})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or POST required"})
	}
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": s.store.Hosts()})
}

// handleHost serves /v1/hosts/{id}/mode.
func (s *Server) handleHost(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v1/hosts/")
	id, action, _ := strings.Cut(rest, "/")
	if id == "" || action != "mode" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var req struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !Modes[req.Mode] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mode must be observe, protect, or lockdown"})
		return
	}
	if !s.store.SetMode(id, req.Mode) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown host"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "host_id": id, "mode": req.Mode})
}
