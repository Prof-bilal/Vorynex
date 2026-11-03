package discovery

import "testing"

func TestRuntime(t *testing.T) {
	cases := []struct {
		image string
		name  string
		want  string
	}{
		{"node:22-alpine", "api", "node"},
		{"myorg/nextjs-app", "web", "nextjs"},
		{"ghcr.io/acme/express-api:1.2", "api", "express"},
		{"postgres:16", "db", "unknown"},
		{"registry.local/npm-runner", "runner", "node"},
	}
	for _, tc := range cases {
		got := Runtime(Container{Image: tc.image, Names: []string{"/" + tc.name}})
		if got != tc.want {
			t.Errorf("Runtime(%q,%q) = %q, want %q", tc.image, tc.name, got, tc.want)
		}
	}
}

func TestNameTrimsSlash(t *testing.T) {
	if got := (Container{Names: []string{"/payments-api"}}).Name(); got != "payments-api" {
		t.Errorf("Name() = %q, want payments-api", got)
	}
	if got := (Container{ID: "abc"}).Name(); got != "abc" {
		t.Errorf("Name() with no names = %q, want abc", got)
	}
}
