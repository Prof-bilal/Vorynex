package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/vorynex/vorynex/engine/cve"
)

// runCve implements `vorynex cve scan`.
func runCve(args []string) error {
	if len(args) == 0 || args[0] != "scan" {
		return fmt.Errorf("usage: vorynex cve scan --lockfile <package-lock.json> (--osv <file> | --live) [--kev <file>|--kev-live] [--workload <name>] [--json]")
	}
	var lockPath, osvPath, kevPath, workload string
	var jsonOut, live, kevLive bool
	timeout := 20 * time.Second
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--lockfile":
			if i+1 < len(args) {
				i++
				lockPath = args[i]
			}
		case "--osv":
			if i+1 < len(args) {
				i++
				osvPath = args[i]
			}
		case "--kev":
			if i+1 < len(args) {
				i++
				kevPath = args[i]
			}
		case "--workload":
			if i+1 < len(args) {
				i++
				workload = args[i]
			}
		case "--json":
			jsonOut = true
		case "--live":
			live = true
		case "--kev-live":
			kevLive = true
		case "--timeout":
			if i+1 < len(args) {
				i++
				if d, err := time.ParseDuration(args[i]); err == nil {
					timeout = d
				}
			}
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}
	if lockPath == "" {
		return fmt.Errorf("--lockfile is required")
	}
	if workload == "" {
		workload = "workload"
	}

	pkgs, err := readLockfile(lockPath)
	if err != nil {
		return err
	}

	ctx := context.Background()
	client := cve.NewClient()
	client.HTTP.Timeout = timeout

	var advisories []cve.Advisory
	if live {
		for _, p := range pkgs {
			advs, err := client.QueryOSV(ctx, p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "osv %s: %v\n", p.Name, err)
				continue
			}
			advisories = append(advisories, advs...)
		}
	} else {
		if osvPath == "" {
			return fmt.Errorf("--osv <file> or --live is required")
		}
		af, err := os.Open(osvPath)
		if err != nil {
			return err
		}
		advisories, err = cve.ParseOSV(af)
		af.Close()
		if err != nil {
			return err
		}
	}

	var kevSet map[string]bool
	if kevLive {
		kevSet, err = client.FetchKEV(ctx)
		if err != nil {
			return err
		}
	} else if kevPath != "" {
		kf, err := os.Open(kevPath)
		if err != nil {
			return err
		}
		kevSet, err = cve.ParseKEV(kf)
		kf.Close()
		if err != nil {
			return err
		}
	}

	matches := cve.Correlate(workload, pkgs, advisories, kevSet)
	if jsonOut {
		b, _ := json.MarshalIndent(matches, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	exploited := 0
	for _, m := range matches {
		if m.Advisory.KnownExploited {
			exploited++
		}
	}
	source := "file"
	if live {
		source = "OSV live"
	}
	fmt.Printf("CVE scan: %s (%d packages, %d advisories, %s)\n\n", workload, len(pkgs), len(advisories), source)
	if len(matches) == 0 {
		fmt.Println("No affected packages found.")
		return nil
	}

	fmt.Printf("%-9s %-30s %-22s %-10s %-10s\n", "EXPLOITED", "ADVISORY", "PACKAGE", "INSTALLED", "FIXED")
	for _, m := range matches {
		flag := ""
		if m.Advisory.KnownExploited {
			flag = "yes"
		}
		id := m.Advisory.ID
		if len(m.Advisory.Aliases) > 0 {
			id += " (" + strings.Join(m.Advisory.Aliases, ", ") + ")"
		}
		fixed := m.Fixed
		if fixed == "" {
			fixed = "unknown"
		}
		fmt.Printf("%-9s %-30s %-22s %-10s %-10s\n", flag, id, m.Package.Name, m.Package.Version, fixed)
		if m.Advisory.Summary != "" {
			fmt.Printf("          %s\n", m.Advisory.Summary)
		}
	}
	fmt.Printf("\n%d match(es), %d known-exploited.\n", len(matches), exploited)
	return nil
}

type lockDoc struct {
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
	Dependencies map[string]struct {
		Version string `json:"version"`
	} `json:"dependencies"`
}

// readLockfile extracts npm packages and versions from package-lock.json (v2/v3
// "packages" or v1 "dependencies").
func readLockfile(path string) ([]cve.Package, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc lockDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}

	seen := map[string]bool{}
	var out []cve.Package
	for key, p := range doc.Packages {
		i := strings.LastIndex(key, "node_modules/")
		if i < 0 || p.Version == "" {
			continue
		}
		name := key[i+len("node_modules/"):]
		if name == "" || seen[name+"@"+p.Version] {
			continue
		}
		seen[name+"@"+p.Version] = true
		out = append(out, cve.Package{Name: name, Version: p.Version, Ecosystem: "npm"})
	}
	if len(out) == 0 {
		for name, p := range doc.Dependencies {
			if p.Version == "" {
				continue
			}
			out = append(out, cve.Package{Name: name, Version: p.Version, Ecosystem: "npm"})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out, nil
}
