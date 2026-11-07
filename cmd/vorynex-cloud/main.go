// Command vorynex-cloud runs the Vorynex Cloud control plane (MVP): the
// ingestion API plus the dashboard.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/vorynex/vorynex/cloud/api"
)

// Stamped at build time (see `make release`).
var version = "0.0.1-dev"

// resolvedDashboard returns a dashboard directory that exists: the one asked
// for, else the system location used by packages, else the original (so the
// 404 explains the path that was actually missing).
func resolvedDashboard(dir string) string {
	if _, err := os.Stat(dir); err == nil {
		return dir
	}
	for _, fallback := range []string{"/usr/share/vorynex/dashboard", "/usr/local/share/vorynex/dashboard"} {
		if _, err := os.Stat(fallback); err == nil {
			return fallback
		}
	}
	return dir
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "listen address")
	token := flag.String("token", "", "bearer admin token required from agents and the dashboard (empty disables auth)")
	store := flag.String("store", "vorynex-cloud/events.jsonl", "event store path")
	dashboard := flag.String("dashboard", "cloud/dashboard", "dashboard static directory")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (with --tls-key) enables HTTPS")
	tlsKey := flag.String("tls-key", "", "TLS private key file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("vorynex-cloud %s\n", version)
		return
	}
	*dashboard = resolvedDashboard(*dashboard)

	eventStore := api.NewStore(*store)
	if mirror := api.NewSupabaseMirrorFromEnv(); mirror != nil {
		eventStore.EnableSupabase(mirror)
		log.Printf("supabase mirror enabled: %s (durable fleet state in Postgres)", mirror.Endpoint())
	} else {
		log.Printf("supabase mirror disabled (set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY to persist fleet state in Postgres)")
	}
	apiHandler := api.New(*token, eventStore).Handler()

	mux := http.NewServeMux()
	mux.Handle("/v1/", apiHandler)
	if _, err := os.Stat(*dashboard); err == nil {
		mux.Handle("/", http.FileServer(http.Dir(*dashboard)))
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "dashboard directory not found: "+*dashboard, http.StatusNotFound)
		})
	}

	if *tlsCert != "" && *tlsKey != "" {
		log.Printf("vorynex-cloud listening on %s over TLS (store %s, dashboard %s)", *addr, *store, *dashboard)
		if err := http.ListenAndServeTLS(*addr, *tlsCert, *tlsKey, mux); err != nil {
			log.Fatal(err)
		}
		return
	}
	log.Printf("vorynex-cloud listening on %s (store %s, dashboard %s) — set --tls-cert/--tls-key for HTTPS, or terminate TLS at a reverse proxy", *addr, *store, *dashboard)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatal(err)
	}
}
