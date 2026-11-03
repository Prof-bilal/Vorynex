package discovery

import (
	"testing"
)

func TestSecretEnvNames(t *testing.T) {
	env := []string{
		"NODE_ENV=production",
		"PORT=3000",
		"STRIPE_SECRET_KEY=decoy",
		"DATABASE_URL=postgres://user:pw@db/app",
		"AWS_ACCESS_KEY_ID=decoy",
		"HOME=/root",
	}
	got := SecretEnvNames(env)
	want := map[string]bool{"STRIPE_SECRET_KEY": true, "DATABASE_URL": true, "AWS_ACCESS_KEY_ID": true}
	if len(got) != len(want) {
		t.Fatalf("SecretEnvNames = %v, want %d names", got, len(want))
	}
	for _, n := range got {
		if !want[n] {
			t.Errorf("unexpected secret name %q", n)
		}
	}
}

func TestSensitiveMountReason(t *testing.T) {
	cases := []struct {
		m    Mount
		want string
	}{
		{Mount{Type: "bind", Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock"}, "docker socket (container escape)"},
		{Mount{Type: "bind", Source: "/root", Destination: "/hostroot"}, "sensitive host path"},
		{Mount{Type: "bind", Source: "/srv/app/.env", Destination: "/app/.env"}, "credential file"},
		{Mount{Type: "bind", Source: "/srv/app", Destination: "/app"}, ""},
		{Mount{Type: "volume", Source: "data", Destination: "/var/lib/data"}, ""},
	}
	for _, tc := range cases {
		if got := sensitiveMountReason(tc.m); got != tc.want {
			t.Errorf("sensitiveMountReason(%+v) = %q, want %q", tc.m, got, tc.want)
		}
	}
}
