package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"
)

// Inspect is the subset of `docker inspect` Vorynex uses to understand what a
// workload can reach before it is protected.
type Inspect struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	State struct {
		Status string `json:"Status"`
		Pid    int    `json:"Pid"`
	} `json:"State"`
	Config struct {
		Image      string   `json:"Image"`
		Env        []string `json:"Env"`
		WorkingDir string   `json:"WorkingDir"`
		User       string   `json:"User"`
		Cmd        []string `json:"Cmd"`
		Entrypoint []string `json:"Entrypoint"`
	} `json:"Config"`
	HostConfig struct {
		NetworkMode    string `json:"NetworkMode"`
		ReadonlyRootfs bool   `json:"ReadonlyRootfs"`
		Privileged     bool   `json:"Privileged"`
	} `json:"HostConfig"`
	Mounts []Mount `json:"Mounts"`
}

// Mount is one container mount.
type Mount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	Mode        string `json:"Mode"`
	RW          bool   `json:"RW"`
}

// SensitiveMount is a mount that gives a compromised workload dangerous reach.
type SensitiveMount struct {
	Destination string `json:"destination"`
	Source      string `json:"source"`
	Reason      string `json:"reason"`
}

// Report is the discovery result for one workload.
type Report struct {
	ID             string
	Name           string
	Image          string
	Runtime        string
	User           string
	NetworkMode    string
	ReadonlyRootfs bool
	Privileged     bool

	WritablePaths   []string
	ReadOnlyPaths   []string
	SensitiveMounts []SensitiveMount
	SecretEnvNames  []string
	PublishedPorts  []Port
	Warnings        []string
}

// sensitiveEnvMarkers are substrings that mark an environment variable NAME as
// likely-secret. Only names are ever read; values are never inspected or stored.
var sensitiveEnvMarkers = []string{
	"TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "APIKEY",
	"PRIVATE", "CREDENTIAL", "_KEY", "ACCESS_KEY", "DATABASE_URL",
}

// sensitiveFilenames are basenames that commonly hold credentials.
var sensitiveFilenames = []string{
	".env", "id_rsa", "id_ed25519", "credentials", ".npmrc", ".pypirc",
	".dockercfg", ".netrc", ".pgpass", ".htpasswd",
}

// sensitiveDestDirs are path fragments whose mount is dangerous inside a workload.
var sensitiveDestDirs = []string{".ssh", ".aws", ".kube", ".docker", ".gnupg"}

// InspectContainer fetches the full configuration for one container.
func InspectContainer(ctx context.Context, id string) (Inspect, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/"+id+"/json", nil)
	if err != nil {
		return Inspect{}, err
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		return Inspect{}, fmt.Errorf("inspect docker container: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Inspect{}, fmt.Errorf("docker inspect returned HTTP %d", resp.StatusCode)
	}
	var out Inspect
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Inspect{}, fmt.Errorf("decode docker inspect: %w", err)
	}
	return out, nil
}

// BuildReport inspects a container and classifies what it can reach. Everything
// here is derived from real configuration, never guessed.
func BuildReport(ctx context.Context, c Container) (Report, error) {
	in, err := InspectContainer(ctx, c.ID)
	if err != nil {
		return Report{}, err
	}
	r := Report{
		ID:             c.ID,
		Name:           c.Name(),
		Image:          in.Config.Image,
		Runtime:        Runtime(c),
		User:           in.Config.User,
		NetworkMode:    in.HostConfig.NetworkMode,
		ReadonlyRootfs: in.HostConfig.ReadonlyRootfs,
		Privileged:     in.HostConfig.Privileged,
		PublishedPorts: c.Ports,
		SecretEnvNames: SecretEnvNames(in.Config.Env),
	}

	seenWrite := map[string]bool{}
	seenRead := map[string]bool{}
	for _, m := range in.Mounts {
		if m.RW {
			if !seenWrite[m.Destination] {
				r.WritablePaths = append(r.WritablePaths, m.Destination)
				seenWrite[m.Destination] = true
			}
		} else if !seenRead[m.Destination] {
			r.ReadOnlyPaths = append(r.ReadOnlyPaths, m.Destination)
			seenRead[m.Destination] = true
		}
		if reason := sensitiveMountReason(m); reason != "" {
			r.SensitiveMounts = append(r.SensitiveMounts, SensitiveMount{
				Destination: m.Destination, Source: m.Source, Reason: reason,
			})
		}
	}
	if wd := in.Config.WorkingDir; wd != "" && wd != "/" && !seenWrite[wd] {
		r.WritablePaths = append(r.WritablePaths, wd+" (working dir)")
	}
	sort.Strings(r.WritablePaths)
	sort.Strings(r.ReadOnlyPaths)

	if r.Privileged {
		r.Warnings = append(r.Warnings, "container runs privileged — the sandbox cannot contain it")
	}
	if r.NetworkMode == "" || r.NetworkMode == "host" {
		r.Warnings = append(r.Warnings, "container uses host networking — egress cannot be restricted")
	}
	if len(r.SensitiveMounts) > 0 {
		r.Warnings = append(r.Warnings, "sensitive mounts present — treat the workload as high blast radius")
	}
	return r, nil
}

// SecretEnvNames returns the names of environment variables that look like
// secrets. Values are never read.
func SecretEnvNames(env []string) []string {
	var out []string
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		up := strings.ToUpper(name)
		for _, marker := range sensitiveEnvMarkers {
			if strings.Contains(up, marker) {
				out = append(out, name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func sensitiveMountReason(m Mount) string {
	dest := m.Destination
	base := path.Base(dest)
	for _, f := range sensitiveFilenames {
		if base == f {
			return "credential file"
		}
	}
	for _, d := range sensitiveDestDirs {
		if dest == d || strings.Contains(dest+"/", d+"/") {
			return "credential directory"
		}
	}
	if m.Type == "bind" {
		switch {
		case strings.HasSuffix(m.Source, "docker.sock"):
			return "docker socket (container escape)"
		case m.Source == "/":
			return "host root filesystem"
		case strings.HasPrefix(m.Source, "/etc"), strings.HasPrefix(m.Source, "/root"),
			strings.HasPrefix(m.Source, "/home"), strings.HasPrefix(m.Source, "/proc"),
			strings.HasPrefix(m.Source, "/sys"):
			return "sensitive host path"
		}
	}
	return ""
}
