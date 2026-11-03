// Package discovery finds the workloads Vorynex can protect on a host.
//
// Milestone 2: Docker/Node workload discovery. It talks to the Docker Engine
// API over the local socket (read-only) and classifies a container's runtime.
// No Docker SDK dependency: a unix-socket HTTP client is enough for the small
// surface we need.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Container is the subset of the Docker container summary Vorynex needs.
type Container struct {
	ID     string   `json:"Id"`
	Names  []string `json:"Names"`
	Image  string   `json:"Image"`
	State  string   `json:"State"`
	Status string   `json:"Status"`
	Ports  []Port   `json:"Ports"`
}

// Port is one published/private port mapping.
type Port struct {
	IP          string `json:"IP,omitempty"`
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort,omitempty"`
	Type        string `json:"Type"`
}

// Name returns the primary container name without Docker's leading slash.
func (c Container) Name() string {
	if len(c.Names) == 0 {
		return c.ID
	}
	return strings.TrimPrefix(c.Names[0], "/")
}

// Runtime classifies the application runtime from image and name hints. This is
// a heuristic; later milestones read the process tree and config for precision.
func Runtime(c Container) string {
	hay := strings.ToLower(c.Image + " " + c.Name())
	switch {
	case strings.Contains(hay, "next"):
		return "nextjs"
	case strings.Contains(hay, "express"):
		return "express"
	case strings.Contains(hay, "node"), strings.Contains(hay, "npm"):
		return "node"
	default:
		return "unknown"
	}
}

// SocketPath is the Docker Engine socket path to use.
func SocketPath() string {
	if h := os.Getenv("DOCKER_HOST"); strings.HasPrefix(h, "unix://") {
		return strings.TrimPrefix(h, "unix://")
	}
	return "/var/run/docker.sock"
}

func httpClient() *http.Client {
	socket := SocketPath()
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}
}

// ListRunning returns the running containers reachable via the Docker socket.
func ListRunning(ctx context.Context) ([]Container, error) {
	if _, err := os.Stat(SocketPath()); err != nil {
		return nil, fmt.Errorf("docker socket not available at %s: %w", SocketPath(), err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("query docker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker returned HTTP %d", resp.StatusCode)
	}
	var out []Container
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode docker response: %w", err)
	}
	return out, nil
}

// NodeWorkloads filters to containers running a Node-family runtime.
func NodeWorkloads(ctx context.Context) ([]Container, error) {
	all, err := ListRunning(ctx)
	if err != nil {
		return nil, err
	}
	var out []Container
	for _, c := range all {
		if r := Runtime(c); r == "node" || r == "nextjs" || r == "express" {
			out = append(out, c)
		}
	}
	return out, nil
}
