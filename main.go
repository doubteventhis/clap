// main.go — CLI for AD domain controller reconnaissance and account enumeration.
//
// Usage:
//   cldap -dc <ip> -cldap -tls -rootdse              # probes, no enum
//   cldap -dc <ip> -cldap -user users.txt             # probe + enum
//   cldap -dc <ip> -user Administrator                # enum only
//   cldap -dc <ip> -user users.txt -computer comps.txt
//
// Probe flags (-cldap, -tls, -rootdse) are opt-in. Each runs an independent
// zero-auth probe against the DC and prints results to stderr.
//
// -rootdse requires -tls (it queries over the LDAPS connection).
//
// The -domain flag is optional. If omitted and -cldap is used, domain is
// auto-discovered. If enumeration is requested without -cldap and without
// -domain, a silent CLDAP probe runs for domain discovery only.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {
	dc       := flag.String("dc", "", "DC IP address (required)")
	domain   := flag.String("domain", "", "Domain name (auto-discovered if omitted)")

	// Probe flags
	doCLDAP   := flag.Bool("cldap", false, "Run CLDAP NETLOGON probe (UDP 389)")
	doTLS     := flag.Bool("tls", false, "Run TLS certificate probe (TCP 636)")
	doRootDSE := flag.Bool("rootdse", false, "Query RootDSE over LDAPS (requires -tls)")

	// Enumeration flags
	user     := flag.String("user", "", "Username or path to username wordlist")
	computer := flag.String("computer", "", "Computer name or path to computer wordlist")

	// Options
	workers  := flag.Int("workers", 10, "Number of concurrent goroutines")
	timeout  := flag.Duration("timeout", 3*time.Second, "Per-request timeout")
	verbose  := flag.Bool("v", false, "Verbose: also print accounts not found")
	quiet    := flag.Bool("q", false, "Quiet: suppress per-account output to stdout (use with -o)")
	outFile  := flag.String("o", "", "Write found account names to file (one per line)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -dc <ip> [probes...] [enumeration...] [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Probes:\n")
		fmt.Fprintf(os.Stderr, "  -cldap     CLDAP NETLOGON probe (UDP 389)\n")
		fmt.Fprintf(os.Stderr, "  -tls       TLS certificate probe (TCP 636)\n")
		fmt.Fprintf(os.Stderr, "  -rootdse   RootDSE query over LDAPS (requires -tls)\n")
		fmt.Fprintf(os.Stderr, "\nEnumeration:\n")
		fmt.Fprintf(os.Stderr, "  -user      Username or path to username wordlist\n")
		fmt.Fprintf(os.Stderr, "  -computer  Computer name or path to computer wordlist\n")
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		fmt.Fprintf(os.Stderr, "  -dc        DC IP address (required)\n")
		fmt.Fprintf(os.Stderr, "  -domain    Domain name (auto-discovered if omitted)\n")
		fmt.Fprintf(os.Stderr, "  -workers   Concurrent goroutines (default 10)\n")
		fmt.Fprintf(os.Stderr, "  -timeout   Per-request timeout (default 3s)\n")
		fmt.Fprintf(os.Stderr, "  -v         Verbose: also print accounts not found\n")
		fmt.Fprintf(os.Stderr, "  -q         Quiet: suppress per-account stdout output\n")
		fmt.Fprintf(os.Stderr, "  -o         Write found accounts to file\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -dc 10.0.0.1 -cldap -tls -rootdse\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -dc 10.0.0.1 -tls -rootdse\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -dc 10.0.0.1 -tls\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -dc 10.0.0.1 -cldap -user users.txt\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -dc 10.0.0.1 -user Administrator\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -dc 10.0.0.1 -user names.txt -computer machines.txt -workers 20\n", os.Args[0])
	}
	flag.Parse()

	if *dc == "" {
		fmt.Fprintln(os.Stderr, "error: -dc is required")
		flag.Usage()
		os.Exit(1)
	}

	if *doRootDSE && !*doTLS {
		fmt.Fprintln(os.Stderr, "error: -rootdse requires -tls")
		os.Exit(1)
	}

	anyProbe := *doCLDAP || *doTLS
	anyEnum := *user != "" || *computer != ""

	if !anyProbe && !anyEnum {
		fmt.Fprintln(os.Stderr, "error: specify at least one probe (-cldap, -tls) or enumeration target (-user, -computer)")
		flag.Usage()
		os.Exit(1)
	}

	// ── Probe phase ─────────────────────────────────────────────────────────

	// CLDAP probe (also used for domain discovery).
	if *doCLDAP {
		fmt.Fprintf(os.Stderr, "[*] CLDAP probe (UDP 389) ...\n")
		info, err := ProbeDC(*dc, *domain, *timeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] CLDAP probe failed: %v\n\n", err)
		} else {
			fmt.Fprintln(os.Stderr)
			info.Print(os.Stderr)
			fmt.Fprintln(os.Stderr)
			if *domain == "" {
				*domain = info.DnsDomainName
				fmt.Fprintf(os.Stderr, "[*] Auto-discovered domain: %s\n\n", *domain)
			}
		}
	}

	// TLS certificate probe (and optional RootDSE).
	if *doTLS {
		fmt.Fprintf(os.Stderr, "[*] TLS probe (TCP 636) ...\n")
		tlsInfo, tlsConn, err := ProbeTLS(*dc, *timeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] TLS probe failed: %v\n\n", err)
		} else {
			fmt.Fprintln(os.Stderr)
			tlsInfo.Print(os.Stderr)

			if *doRootDSE {
				fmt.Fprintf(os.Stderr, "\n[*] RootDSE query over LDAPS ...\n")
				dseInfo, err := ProbeRootDSE(tlsConn, *timeout)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] RootDSE query failed: %v\n\n", err)
				} else {
					fmt.Fprintln(os.Stderr)
					dseInfo.Print(os.Stderr)
				}
			}

			tlsConn.Close()
			fmt.Fprintln(os.Stderr)
		}
	}

	// ── Enumeration phase ───────────────────────────────────────────────────

	if !anyEnum {
		return
	}

	// Domain discovery: if not already known, silently probe.
	if *domain == "" {
		info, err := ProbeDC(*dc, "", *timeout)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: could not discover domain (probe failed and no -domain specified)")
			os.Exit(1)
		}
		*domain = info.DnsDomainName
		fmt.Fprintf(os.Stderr, "[*] Auto-discovered domain: %s\n", *domain)
	}

	// Open output file if requested.
	var outW *bufio.Writer
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot create output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		outW = bufio.NewWriter(f)
		defer outW.Flush()
	}

	// Build enumeration jobs.
	type job struct {
		name string
		aac  []byte
	}
	var jobs []job

	if *user != "" {
		names := loadNames(*user)
		for _, n := range names {
			jobs = append(jobs, job{name: n, aac: AACUser})
		}
		fmt.Fprintf(os.Stderr, "[*] User accounts to test: %d  (AAC=0x00000010)\n", len(names))
	}
	if *computer != "" {
		names := loadNames(*computer)
		for _, n := range names {
			jobs = append(jobs, job{name: n, aac: AACComputer})
		}
		fmt.Fprintf(os.Stderr, "[*] Computer accounts to test: %d  (AAC=0x000001C0)\n", len(names))
	}

	if len(jobs) == 0 {
		fmt.Fprintln(os.Stderr, "error: no account names to test")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "[*] %d total name(s), %d workers, timeout %v\n", len(jobs), *workers, *timeout)
	if *outFile != "" {
		fmt.Fprintf(os.Stderr, "[*] Writing results to %s\n", *outFile)
	}
	fmt.Fprintln(os.Stderr)

	type result struct {
		name   string
		exists bool
		err    error
	}

	jobCh := make(chan job, len(jobs))
	results := make(chan result, len(jobs))

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobCh {
				exists, err := CheckAccount(*dc, *domain, j.name, j.aac, *timeout)
				results <- result{name: j.name, exists: exists, err: err}
			}
		}()
	}

	for _, j := range jobs {
		jobCh <- j
	}
	close(jobCh)

	go func() {
		wg.Wait()
		close(results)
	}()

	found, notFound, errCount := 0, 0, 0
	for r := range results {
		switch {
		case r.err != nil:
			if !*quiet {
				fmt.Printf("[!] %-20s  error: %v\n", r.name, r.err)
			}
			errCount++
		case r.exists:
			if !*quiet {
				fmt.Println(r.name)
			}
			if outW != nil {
				fmt.Fprintln(outW, r.name)
			}
			found++
		default:
			if !*quiet && *verbose {
				fmt.Printf("[-] %s\n", r.name)
			}
			notFound++
		}
	}

	fmt.Fprintf(os.Stderr, "\n[*] Done — found: %d  not found: %d  errors: %d\n", found, notFound, errCount)
}

// loadNames returns account names from val. If val is a readable file, names
// are loaded line-by-line (blank lines and #comments skipped). Otherwise val
// itself is returned as a single-element list.
func loadNames(val string) []string {
	f, err := os.Open(val)
	if err != nil {
		// Not a file — treat as a single account name.
		return []string{val}
	}
	defer f.Close()

	var names []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if u := strings.TrimSpace(sc.Text()); u != "" && !strings.HasPrefix(u, "#") {
			names = append(names, u)
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "error reading %s: %v\n", val, err)
		os.Exit(1)
	}
	return names
}
