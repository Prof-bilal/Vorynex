// Command vorynex-cloud runs the Vorynex Cloud ingestion API (MVP control plane).
package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/vorynex/vorynex/cloud/api"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "listen address")
	token := flag.String("token", "", "bearer token required from agents (empty disables auth)")
	store := flag.String("store", "vorynex-cloud/events.jsonl", "event store path")
	flag.Parse()

	srv := api.New(*token, api.NewStore(*store))
	log.Printf("vorynex-cloud listening on %s (store %s)", *addr, *store)
	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		log.Fatal(err)
	}
}
