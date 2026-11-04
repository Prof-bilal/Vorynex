// Package api is the Vorynex Cloud ingestion API: the control-plane entry point
// for host enrollment, telemetry, and workload protection mode. It is
// deliberately out of the application's request path — a cloud outage must not
// affect enforcement.
package api

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vorynex/vorynex/engine/blastradius"
	"github.com/vorynex/vorynex/engine/policy"
	"github.com/vorynex/vorynex/engine/telemetry"
)

// Host is an enrolled agent.
type Host struct {
	ID           string    `json:"host_id"`
	Hostname     string    `json:"hostname"`
	Mode         string    `json:"mode"` // observe | protect | lockdown
	RegisteredAt time.Time `json:"registered_at"`
	// Token is the per-host bearer token issued at enrollment. It is never
	// returned in host listings.
	Token         string    `json:"token,omitempty"`
	TokenIssuedAt time.Time `json:"token_issued_at,omitempty"`
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
	mu       sync.Mutex
	path     string
	hosts    map[string]Host
	policies map[string]string
	desired  map[string]RolloutState
	sboms    map[string]json.RawMessage
}

// RolloutState is the desired state the control plane wants a host to run.
type RolloutState struct {
	HostID     string    `json:"host_id"`
	Revision   int       `json:"revision"`
	Mode       string    `json:"mode"`
	PolicyYAML string    `json:"policy_yaml,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// NewStore opens (creating if needed) a store at path.
func NewStore(path string) *Store {
	st := &Store{path: path, hosts: map[string]Host{}, policies: map[string]string{}, desired: map[string]RolloutState{}, sboms: map[string]json.RawMessage{}}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	if f, err := os.Open(path + ".sboms"); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 8*1024), 8<<20)
		for sc.Scan() {
			if len(sc.Bytes()) == 0 {
				continue
			}
			var rec sbomRecord
			if json.Unmarshal(sc.Bytes(), &rec) == nil && rec.HostID != "" {
				st.sboms[rec.HostID] = rec.SBOM
			}
		}
		f.Close()
	}
	if f, err := os.Open(path + ".desired"); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 8*1024), 8<<20)
		for sc.Scan() {
			if len(sc.Bytes()) == 0 {
				continue
			}
			var rs RolloutState
			if json.Unmarshal(sc.Bytes(), &rs) == nil && rs.HostID != "" {
				st.desired[rs.HostID] = rs
			}
		}
		f.Close()
	}
	if f, err := os.Open(path + ".policies"); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 8*1024), 8<<20)
		for sc.Scan() {
			if len(sc.Bytes()) == 0 {
				continue
			}
			var rec policyRecord
			if json.Unmarshal(sc.Bytes(), &rec) == nil && rec.HostID != "" {
				st.policies[rec.HostID] = rec.YAML
			}
		}
		f.Close()
	}
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

// Hosts returns the enrolled hosts sorted by id, with tokens redacted.
func (st *Store) Hosts() []Host {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]Host, 0, len(st.hosts))
	for _, h := range st.hosts {
		h.Token = ""
		h.TokenIssuedAt = time.Time{}
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// IssueToken creates (or replaces) a host's per-host token.
func (st *Store) IssueToken(id string) (string, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	h, ok := st.hosts[id]
	if !ok {
		return "", false
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", false
	}
	h.Token = hex.EncodeToString(buf)
	h.TokenIssuedAt = time.Now().UTC()
	st.hosts[id] = h
	st.saveHostsLocked()
	return h.Token, true
}

// HostToken returns a host's per-host token ("" if none).
func (st *Store) HostToken(id string) string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.hosts[id].Token
}

// SetDesired records the desired rollout state, bumping the revision.
func (st *Store) SetDesired(id, mode, policyYAML string) (RolloutState, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.hosts[id]; !ok {
		return RolloutState{}, false
	}
	rs := st.desired[id]
	rs.HostID = id
	rs.Revision++
	rs.Mode = mode
	if policyYAML != "" {
		rs.PolicyYAML = policyYAML
	}
	rs.UpdatedAt = time.Now().UTC()
	st.desired[id] = rs
	st.saveDesiredLocked()
	return rs, true
}

// Desired returns a host's desired rollout state.
func (st *Store) Desired(id string) (RolloutState, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	rs, ok := st.desired[id]
	return rs, ok
}

// sbomRecord is the persisted form of an uploaded SBOM.
type sbomRecord struct {
	HostID string          `json:"host_id"`
	SBOM   json.RawMessage `json:"sbom"`
}

// SetSBOM stores a host's uploaded SBOM.
func (st *Store) SetSBOM(id string, sbom json.RawMessage) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sboms[id] = sbom
	st.saveSBOMsLocked()
}

// GetSBOM returns a host's uploaded SBOM.
func (st *Store) GetSBOM(id string) (json.RawMessage, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	v, ok := st.sboms[id]
	return v, ok
}

func (st *Store) saveSBOMsLocked() {
	f, err := os.Create(st.path + ".sboms")
	if err != nil {
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for host, sbom := range st.sboms {
		b, _ := json.Marshal(sbomRecord{HostID: host, SBOM: sbom})
		w.Write(append(b, '\n'))
	}
	w.Flush()
}

func (st *Store) saveDesiredLocked() {
	f, err := os.Create(st.path + ".desired")
	if err != nil {
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, rs := range st.desired {
		b, _ := json.Marshal(rs)
		w.Write(append(b, '\n'))
	}
	w.Flush()
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

// policyRecord is the persisted form of an uploaded policy.
type policyRecord struct {
	HostID string `json:"host_id"`
	YAML   string `json:"yaml"`
}

// SetPolicy stores the effective policy YAML for a host.
func (st *Store) SetPolicy(hostID, yaml string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.policies[hostID] = yaml
	st.savePoliciesLocked()
}

// GetPolicy returns a host's uploaded policy.
func (st *Store) GetPolicy(hostID string) (string, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	v, ok := st.policies[hostID]
	return v, ok
}

func (st *Store) savePoliciesLocked() {
	f, err := os.Create(st.path + ".policies")
	if err != nil {
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for host, yaml := range st.policies {
		b, _ := json.Marshal(policyRecord{HostID: host, YAML: yaml})
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

func bearerToken(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func (s *Server) authorized(r *http.Request) bool {
	if s.token == "" {
		return true
	}
	return bearerToken(r) == s.token
}

// authorizedForHost accepts the admin token or that host's own token. Agents use
// their per-host token, so a leaked agent credential cannot touch other hosts.
func (s *Server) authorizedForHost(r *http.Request, hostID string) bool {
	if s.authorized(r) {
		return true
	}
	tok := s.store.HostToken(hostID)
	return tok != "" && bearerToken(r) == tok
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
	resp := map[string]any{"ok": true}
	issued := ""
	if s.token != "" && s.store.HostToken(req.HostID) == "" {
		if tok, ok := s.store.IssueToken(req.HostID); ok {
			issued = tok
		}
	}
	h.Token = ""
	resp["host"] = h
	if issued != "" {
		resp["host_token"] = issued
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !s.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
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
		if !s.authorizedForHost(r, req.HostID) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
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

// handleHost serves /v1/hosts/{id}/{mode|policy|rotate-token}.
func (s *Server) handleHost(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/hosts/")
	id, action, _ := strings.Cut(rest, "/")
	if id == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	switch action {
	case "mode":
		if !s.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		s.handleMode(w, r, id)
	case "rotate-token":
		if !s.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		s.handleRotateToken(w, r, id)
	case "policy":
		if !s.authorizedForHost(r, id) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		s.handlePolicy(w, r, id)
	case "rollout":
		if !s.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		s.handleRollout(w, r, id)
	case "desired":
		if !s.authorizedForHost(r, id) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		s.handleDesired(w, r, id)
	case "sbom":
		if !s.authorizedForHost(r, id) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		s.handleSBOM(w, r, id)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

// handleRollout stages a desired mode (and optional policy) for a host. The
// policy is validated deterministically before it is accepted; nothing is
// applied anywhere until the agent pulls it and the supervisor launches under it.
func (s *Server) handleRollout(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var req struct {
		Mode string `json:"mode"`
		YAML string `json:"policy_yaml"`
	}
	if err := json.Unmarshal(body, &req); err != nil || !Modes[req.Mode] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mode must be observe, protect, or lockdown"})
		return
	}
	if strings.TrimSpace(req.YAML) != "" {
		if _, err := parsePolicyYAML(req.YAML); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "invalid policy: " + err.Error()})
			return
		}
	}
	rs, ok := s.store.SetDesired(id, req.Mode, req.YAML)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown host"})
		return
	}
	s.store.SetMode(id, req.Mode)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rollout": rs})
}

// handleDesired returns the desired state an agent should converge to.
func (s *Server) handleDesired(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
		return
	}
	rs, ok := s.store.Desired(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no desired state for this host"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rollout": rs})
}

// handleSBOM stores (POST) and returns (GET) a host's correlated SBOM.
func (s *Server) handleSBOM(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodGet:
		sbom, ok := s.store.GetSBOM(id)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no SBOM uploaded for this host"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"host_id": id, "sbom": sbom})
	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		var req struct {
			SBOM json.RawMessage `json:"sbom"`
		}
		if err := json.Unmarshal(body, &req); err != nil || len(req.SBOM) == 0 || !json.Valid(req.SBOM) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "valid sbom required"})
			return
		}
		s.store.SetSBOM(id, req.SBOM)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "host_id": id})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or POST required"})
	}
}

// handleRotateToken issues a fresh per-host token (admin only). The old token
// stops working immediately.
func (s *Server) handleRotateToken(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	tok, ok := s.store.IssueToken(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown host"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "host_id": id, "host_token": tok})
}

func (s *Server) handleMode(w http.ResponseWriter, r *http.Request, id string) {
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

// policySummary is the reviewable shape of an uploaded policy.
type policySummary struct {
	Version        int      `json:"version"`
	Read           []string `json:"read"`
	Write          []string `json:"write"`
	Deny           []string `json:"deny"`
	ExecAllow      []string `json:"exec_allow"`
	ExecDeny       []string `json:"exec_deny"`
	NetworkAllow   []string `json:"network_allow"`
	ProtectSecrets bool     `json:"protect_secrets"`
}

func summarise(p policy.Policy) policySummary {
	return policySummary{
		Version:        p.Version,
		Read:           p.Filesystem.Read,
		Write:          p.Filesystem.Write,
		Deny:           p.Filesystem.Deny,
		ExecAllow:      p.Process.Exec.Allow,
		ExecDeny:       p.Process.Exec.Deny,
		NetworkAllow:   p.Network.Allow,
		ProtectSecrets: p.Filesystem.ProtectSecrets,
	}
}

func parsePolicyYAML(yaml string) (policy.Policy, error) {
	f, err := os.CreateTemp("", "vorynex-upload-*.yaml")
	if err != nil {
		return policy.Policy{}, err
	}
	path := f.Name()
	defer os.Remove(path)
	if _, err := f.WriteString(yaml); err != nil {
		f.Close()
		return policy.Policy{}, err
	}
	f.Close()
	return policy.Load(path)
}

// handlePolicy stores (POST) and returns (GET) the effective policy for a host.
// GET includes a policy-derived blast radius; nothing here is invented.
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodGet:
		yaml, ok := s.store.GetPolicy(id)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no policy uploaded for this host"})
			return
		}
		p, err := parsePolicyYAML(yaml)
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "stored policy is invalid: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"host_id":      id,
			"yaml":         yaml,
			"summary":      summarise(p),
			"blast_radius": blastradius.FromPolicy(p, id, ""),
		})
	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		var req struct {
			YAML string `json:"yaml"`
		}
		if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.YAML) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "yaml required"})
			return
		}
		if _, err := parsePolicyYAML(req.YAML); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "invalid policy: " + err.Error()})
			return
		}
		s.store.SetPolicy(id, req.YAML)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "host_id": id})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or POST required"})
	}
}
