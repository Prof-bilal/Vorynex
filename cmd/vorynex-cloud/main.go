// Command vorynex-cloud runs the Vorynex Cloud control plane (MVP): the
// ingestion API plus the dashboard.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/vorynex/vorynex/cloud/api"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "listen address")
	token := flag.String("token", "", "bearer admin token required from agents and the dashboard (empty disables auth)")
	store := flag.String("store", "vorynex-cloud/events.jsonl", "event store path")
	dashboard := flag.String("dashboard", "cloud/dashboard", "dashboard static directory")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (with --tls-key) enables HTTPS")
	tlsKey := flag.String("tls-key", "", "TLS private key file")
	flag.Parse()

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
