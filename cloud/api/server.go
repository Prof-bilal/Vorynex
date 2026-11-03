// Package api is the Vorynex Cloud ingestion API: the control-plane entry point
// for host enrollment and telemetry. It is deliberately out of the application's
// request path — a cloud outage must not affect enforcement.
package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/vorynex/vorynex/engine/telemetry"
)

// Store persists enrolled hosts and ingested events. It uses a JSONL file so
// the MVP has no database dependency; a real store replaces it later.
type Store struct {
	mu    sync.Mutex
	path  string
	hosts map[string]bool
}

// NewStore opens (creating if needed) a store at path.
func NewStore(path string) *Store {
	st := &Store{path: path, hosts: map[string]bool{}}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	if b, err := os.ReadFile(path + ".hosts"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				st.hosts[line] = true
			}
		}
	}
	return st
}

// RegisterHost records an enrolled host. It returns true if the host is new.
func (st *Store) RegisterHost(id string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.hosts[id] {
		return false
	}
	st.hosts[id] = true
	f, err := os.OpenFile(st.path+".hosts", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err == nil {
		f.WriteString(id + "\n")
		f.Close()
	}
	return true
}

// Hosts returns the enrolled host ids.
func (st *Store) Hosts() []string {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]string, 0, len(st.hosts))
	for id := range st.hosts {
		out = append(out, id)
	}
	return out
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
		row := struct {
			Host   string           `json:"host_id"`
			Record telemetry.Record `json:"record"`
		}{hostID, r}
		b, err := json.Marshal(row)
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

// Server is the ingestion HTTP API.
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
	newHost := s.store.RegisterHost(req.HostID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "new_host": newHost})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	if !s.authorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req struct {
		HostID  string             `json:"host_id"`
		Records []telemetry.Record `json:"records"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.HostID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host_id and records required"})
		return
	}
	s.store.RegisterHost(req.HostID) // ingest implies enrolled
	accepted, err := s.store.AppendRecords(req.HostID, req.Records)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"accepted": accepted})
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": s.store.Hosts()})
}
