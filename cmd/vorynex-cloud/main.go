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
	token := flag.String("token", "", "bearer token required from agents and the dashboard (empty disables auth)")
	store := flag.String("store", "vorynex-cloud/events.jsonl", "event store path")
	dashboard := flag.String("dashboard", "cloud/dashboard", "dashboard static directory")
	flag.Parse()

	apiHandler := api.New(*token, api.NewStore(*store)).Handler()

	mux := http.NewServeMux()
	mux.Handle("/v1/", apiHandler)
	if _, err := os.Stat(*dashboard); err == nil {
		mux.Handle("/", http.FileServer(http.Dir(*dashboard)))
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "dashboard directory not found: "+*dashboard, http.StatusNotFound)
		})
	}

	log.Printf("vorynex-cloud listening on %s (store %s, dashboard %s)", *addr, *store, *dashboard)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatal(err)
	}
}
