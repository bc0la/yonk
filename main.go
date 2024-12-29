package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	allowlist string
	port      string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "myserver [directory]",
		Short: "Serve a static directory with an optional IP allowlist.",
		Long: `Serve a static directory with an optional IP allowlist,
logging all incoming requests and denying those not in the allowlist.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := args[0]

			absDir, err := filepath.Abs(dir)
			if err != nil {
				return fmt.Errorf("error resolving directory: %w", err)
			}

			var allowedIPs map[string]bool
			if allowlist != "" {
				allowedIPs, err = parseAllowlist(allowlist)
				if err != nil {
					return fmt.Errorf("error parsing allowlist: %w", err)
				}
				log.Printf("Allowlist: %v", mapKeys(allowedIPs))
			} else {
				log.Println("Warning: no allowlist, all IPs allowed.")
			}

			fs := http.FileServer(http.Dir(absDir))
			handler := withAllowlistCheck(fs, allowedIPs)

			addr := ":" + port
			log.Printf("Serving %s on %s", absDir, addr)
			return http.ListenAndServe(addr, handler)
		},
	}

	rootCmd.Flags().StringVarP(&allowlist, "allowlist", "a", "", "Comma-separated IPs or file with IPs")
	rootCmd.Flags().StringVarP(&port, "port", "p", "8080", "Port to listen on")

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func withAllowlistCheck(next http.Handler, allowedIPs map[string]bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, port, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Printf("Unknown address: %s %s", r.RemoteAddr, r.URL.Path)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		log.Printf("Request from %s:%s -> %s", ip, port, r.URL.Path)

		if allowedIPs == nil {
			next.ServeHTTP(w, r)
			return
		}
		if !allowedIPs[ip] {
			log.Printf("DENIED: %s not in allowlist", ip)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		log.Printf("ALLOWED: %s", ip)
		next.ServeHTTP(w, r)
	})
}

func parseAllowlist(s string) (map[string]bool, error) {
	// If 's' is a file
	if fi, err := os.Stat(s); err == nil && !fi.IsDir() {
		return readAllowlistFile(s)
	}
	// Otherwise, treat as comma-separated list
	ips := strings.Split(s, ",")
	m := make(map[string]bool, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			m[ip] = true
		}
	}
	return m, nil
}

func readAllowlistFile(path string) (map[string]bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	m := make(map[string]bool)
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		ip := strings.TrimSpace(sc.Text())
		if ip != "" {
			m[ip] = true
		}
	}
	return m, sc.Err()
}

func mapKeys(m map[string]bool) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
