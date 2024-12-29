package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	allowlist string
	port      string
	noSSL     bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "yonk [directory]",
		Short: "Serve a static directory over HTTP or HTTPS with optional IP allowlist",
		Args:  cobra.ExactArgs(1),
		RunE:  runServer,
	}

	rootCmd.Flags().StringVarP(&allowlist, "allowlist", "a", "", "Comma-separated IPs or file with IPs (all allowed if omitted)")
	rootCmd.Flags().StringVarP(&port, "port", "p", "", "Port to listen on")
	rootCmd.Flags().BoolVarP(&noSSL, "no-ssl", "s", false, "Disable SSL (serve over HTTP)")

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func runServer(cmd *cobra.Command, args []string) error {
	dir := args[0]
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("error resolving directory: %w", err)
	}

	// Determine SSL usage
	useSSL := !noSSL

	// Determine port based on SSL flag and whether port was specified
	if !cmd.Flags().Changed("port") {
		if useSSL {
			port = "443"
		} else {
			port = "80"
		}
	} else if port == "" {
		// If port flag was provided but no value, set default based on SSL
		if useSSL {
			port = "443"
		} else {
			port = "80"
		}
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

		// Add confirmation prompt
		fmt.Printf("Press Enter to continue if you understand the risks, you could be exposing  %q to the world!", absDir)
		reader := bufio.NewReader(os.Stdin)
		_, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("error waiting for user input: %w", err)
		}
	}

	fs := http.FileServer(http.Dir(absDir))
	handler := withAllowlistCheck(fs, allowedIPs)

	addr := ":" + port
	if useSSL {
		log.Printf("Serving %q on HTTPS %s (SSL enabled)", absDir, addr)

		// Generate self-signed certificate
		cert, err := generateSelfSignedCert()
		if err != nil {
			return fmt.Errorf("failed generating self-signed certificate: %w", err)
		}
		srv := &http.Server{
			Addr:      addr,
			Handler:   handler,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		}
		log.Println("Using ephemeral self-signed certificate (browser may warn)...")

		// Serve HTTPS
		return srv.ListenAndServeTLS("", "")
	}

	log.Printf("Serving %q on HTTP %s (SSL disabled)", absDir, addr)
	return http.ListenAndServe(addr, handler)
}

// withAllowlistCheck wraps the handler to enforce IP allowlist
func withAllowlistCheck(next http.Handler, allowedIPs map[string]bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Printf("Unknown address: %s %s", r.RemoteAddr, r.URL.Path)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		log.Printf("Request from %s -> %s", ip, r.URL.Path)

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

// parseAllowlist parses the allowlist string or file into a map
func parseAllowlist(s string) (map[string]bool, error) {
	if fi, err := os.Stat(s); err == nil && !fi.IsDir() {
		return readAllowlistFile(s)
	}
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

// readAllowlistFile reads IPs from a file, one per line
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

// mapKeys returns the keys of a map as a slice
func mapKeys(m map[string]bool) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// generateSelfSignedCert creates an ephemeral self-signed RSA certificate in memory.
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial := big.NewInt(time.Now().UnixNano())
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "yonk-self-signed",
			Organization: []string{"yonk"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour), // Valid for 24 hours

		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}
