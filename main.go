package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// third-party hosts that commonly hold assets *not* owned by the program.
// presence + no keyword match => SUSPICIOUS.
var thirdPartyHosts = []string{
	"herokuapp.com", "herokussl.com",
	"vercel.app", "vercel-dns.com",
	"netlify.app", "netlifyglobalcdn.com",
	"github.io", "githubusercontent.com", "githubpages.com",
	"gitlab.io",
	"cloudfront.net",
	"azurewebsites.net", "azureedge.net", "blob.core.windows.net",
	"appspot.com",
	"s3.amazonaws.com", "s3-website",
	"elasticbeanstalk.com",
	"readthedocs.io",
	"firebaseapp.com",
	"shopifycloud.com", "myshopify.com",
	"wpengine.com",
	"fastly.net",
}

type result struct {
	Asset      string   `json:"asset"`
	Resolves   bool     `json:"resolves"`
	IPs        []string `json:"ips,omitempty"`
	CNAMEs     []string `json:"cnames,omitempty"`
	CertSANs   []string `json:"cert_sans,omitempty"`
	CertIssuer string   `json:"cert_issuer,omitempty"`
	CertSubj   string   `json:"cert_subject,omitempty"`
	HTTPServer string   `json:"http_server,omitempty"`
	Redirect   string   `json:"redirect,omitempty"`
	Score      int      `json:"score"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
	Error      string   `json:"error,omitempty"`
}

type config struct {
	inputPath   string
	programList []string
	outputPath  string
	concurrency int
	timeout     time.Duration
	useColor    bool
	verbose     bool
}

func main() {
	os.Exit(run())
}

func run() int {
	var (
		input    = flag.String("i", "", "path to scope file (one asset per line)")
		program  = flag.String("p", "", "program keyword(s), comma-separated (e.g. 'gitlab,gitlab-inc')")
		output   = flag.String("o", "", "write full JSON results to this path")
		conc     = flag.Int("c", 20, "concurrent workers")
		timeout  = flag.Duration("t", 10*time.Second, "per-probe timeout")
		noColor  = flag.Bool("no-color", false, "disable ANSI color")
		verbose  = flag.Bool("v", false, "verbose logging to stderr")
		showHelp = flag.Bool("h", false, "show help")
	)
	flag.Usage = func() {
		w := flag.CommandLine.Output()
		fmt.Fprintln(w, "scopesift - validate ownership of in-scope assets against a program identity")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "usage:  scopesift -i scope.txt -p 'gitlab,gitlab-inc' [options]")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "required:")
		fmt.Fprintln(w, "  -i <file>        scope file, one asset per line")
		fmt.Fprintln(w, "  -p <kw,kw,...>   program keyword(s) to match against cert/DNS/HTTP evidence")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "optional:")
		fmt.Fprintln(w, "  -o <file>        write full JSON output to file")
		fmt.Fprintln(w, "  -c <n>           concurrent workers (default 20)")
		fmt.Fprintln(w, "  -t <duration>    per-probe timeout (default 10s)")
		fmt.Fprintln(w, "  -v               verbose stderr logging")
		fmt.Fprintln(w, "      --no-color   disable color (also honours NO_COLOR env)")
		fmt.Fprintln(w, "  -h               show this help")
	}
	flag.Parse()

	if *showHelp {
		flag.Usage()
		return 0
	}
	if *input == "" || *program == "" {
		fmt.Fprintln(os.Stderr, "error: -i and -p are required (see -h)")
		return 1
	}

	cfg := config{
		inputPath:   *input,
		programList: splitAndTrim(*program),
		outputPath:  *output,
		concurrency: *conc,
		timeout:     *timeout,
		useColor:    shouldColor(*noColor),
		verbose:     *verbose,
	}
	if cfg.concurrency < 1 {
		cfg.concurrency = 1
	}

	logLevel := slog.LevelWarn
	if cfg.verbose {
		logLevel = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	assets, err := readAssets(cfg.inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading scope file: %v\n", err)
		return 2
	}
	if len(assets) == 0 {
		fmt.Fprintln(os.Stderr, "error: scope file is empty")
		return 1
	}

	results := probeAll(assets, cfg)

	renderTable(results, cfg.useColor)

	if cfg.outputPath != "" {
		if err := writeJSON(cfg.outputPath, results); err != nil {
			fmt.Fprintf(os.Stderr, "error: writing json: %v\n", err)
			return 2
		}
	}
	return 0
}

func shouldColor(flagNoColor bool) bool {
	if flagNoColor {
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("CI") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func readAssets(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// strip scheme if present
		line = strings.TrimPrefix(line, "https://")
		line = strings.TrimPrefix(line, "http://")
		line = strings.TrimSuffix(line, "/")
		line = strings.ToLower(line)
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	return out, nil
}

func probeAll(assets []string, cfg config) []result {
	results := make([]result, len(assets))
	sem := make(chan struct{}, cfg.concurrency)
	var wg sync.WaitGroup
	for i, a := range assets {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, asset string) {
			defer wg.Done()
			defer func() { <-sem }()
			r := probe(asset, cfg)
			results[idx] = r
		}(i, a)
	}
	wg.Wait()
	return results
}

func probe(asset string, cfg config) result {
	r := result{Asset: asset}
	slog.Info("probing", "asset", asset)

	// DNS
	ips, cnames, dnsErr := resolve(asset, cfg.timeout)
	r.IPs = ips
	r.CNAMEs = cnames
	r.Resolves = len(ips) > 0
	if dnsErr != nil && !r.Resolves {
		r.Error = "dns: " + dnsErr.Error()
	}

	// TLS cert (only if resolves and has a hostname, not bare IP)
	if r.Resolves && !isIP(asset) {
		sans, issuer, subj, tlsErr := fetchCert(asset, cfg.timeout)
		if tlsErr != nil {
			slog.Info("tls failed", "asset", asset, "err", tlsErr)
		} else {
			r.CertSANs = sans
			r.CertIssuer = issuer
			r.CertSubj = subj
		}
	}

	// HTTP HEAD
	server, redir, httpErr := httpFingerprint(asset, cfg.timeout)
	if httpErr != nil {
		slog.Info("http failed", "asset", asset, "err", httpErr)
	} else {
		r.HTTPServer = server
		r.Redirect = redir
	}

	score(&r, cfg.programList)
	return r
}

func isIP(s string) bool {
	return net.ParseIP(s) != nil
}

func resolve(host string, timeout time.Duration) ([]string, []string, error) {
	if isIP(host) {
		return []string{host}, nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var r net.Resolver
	ips, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, nil, err
	}
	var cnames []string
	if cname, cerr := r.LookupCNAME(ctx, host); cerr == nil && cname != "" && cname != host+"." {
		cnames = append(cnames, strings.TrimSuffix(cname, "."))
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.IP.String())
	}
	return out, cnames, nil
}

func fetchCert(host string, timeout time.Duration) ([]string, string, string, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, "443"), &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // we're inspecting, not trusting
	})
	if err != nil {
		return nil, "", "", err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, "", "", errors.New("no peer certs")
	}
	c := certs[0]
	sans := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		sans = append(sans, ip.String())
	}
	issuer := c.Issuer.CommonName
	if len(c.Issuer.Organization) > 0 {
		issuer = c.Issuer.Organization[0]
	}
	subj := c.Subject.CommonName
	if len(c.Subject.Organization) > 0 {
		subj = c.Subject.Organization[0]
	}
	return sans, issuer, subj, nil
}

func httpFingerprint(host string, timeout time.Duration) (string, string, error) {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	url := "https://" + host
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "scopesift/0.1 (+github.com/daniyalnasir-root/scopesift)")
	resp, err := client.Do(req)
	if err != nil {
		// fallback to http://
		url = "http://" + host
		req, _ = http.NewRequest(http.MethodHead, url, nil)
		req.Header.Set("User-Agent", "scopesift/0.1")
		resp, err = client.Do(req)
		if err != nil {
			return "", "", err
		}
	}
	defer resp.Body.Close()
	server := resp.Header.Get("Server")
	redir := ""
	if loc := resp.Header.Get("Location"); loc != "" {
		redir = loc
	}
	return server, redir, nil
}

func score(r *result, kws []string) {
	haystack := []string{
		strings.ToLower(r.CertIssuer),
		strings.ToLower(r.CertSubj),
		strings.ToLower(r.HTTPServer),
		strings.ToLower(r.Redirect),
	}
	for _, s := range r.CertSANs {
		haystack = append(haystack, strings.ToLower(s))
	}
	for _, c := range r.CNAMEs {
		haystack = append(haystack, strings.ToLower(c))
	}

	for _, kw := range kws {
		// strong evidence: cert SAN or subject-org match
		for _, san := range r.CertSANs {
			if strings.Contains(strings.ToLower(san), kw) {
				r.Score += 3
				r.Evidence = append(r.Evidence, "cert-san:"+san)
				goto kwDone
			}
		}
		if strings.Contains(strings.ToLower(r.CertSubj), kw) {
			r.Score += 3
			r.Evidence = append(r.Evidence, "cert-subj:"+r.CertSubj)
			continue
		}
		// weaker: CNAME, server header, redirect
		for _, c := range r.CNAMEs {
			if strings.Contains(strings.ToLower(c), kw) {
				r.Score += 2
				r.Evidence = append(r.Evidence, "cname:"+c)
				goto kwDone
			}
		}
		if strings.Contains(strings.ToLower(r.HTTPServer), kw) {
			r.Score++
			r.Evidence = append(r.Evidence, "server:"+r.HTTPServer)
		}
		if strings.Contains(strings.ToLower(r.Redirect), kw) {
			r.Score++
			r.Evidence = append(r.Evidence, "redirect:"+r.Redirect)
		}
	kwDone:
	}

	// suspicious: resolved to a known third-party host, no keyword match
	suspicious := false
	if r.Score == 0 {
		for _, h := range haystack {
			for _, tp := range thirdPartyHosts {
				if strings.Contains(h, tp) {
					suspicious = true
					r.Evidence = append(r.Evidence, "third-party:"+tp)
					break
				}
			}
			if suspicious {
				break
			}
		}
	}

	switch {
	case !r.Resolves:
		r.Confidence = "UNRESOLVED"
	case r.Score >= 3:
		r.Confidence = "HIGH"
	case r.Score >= 1:
		r.Confidence = "MEDIUM"
	case suspicious:
		r.Confidence = "SUSPICIOUS"
	default:
		r.Confidence = "LOW"
	}
}

func renderTable(results []result, color bool) {
	sort.SliceStable(results, func(i, j int) bool {
		return confidenceRank(results[i].Confidence) < confidenceRank(results[j].Confidence)
	})

	assetW, confW, evW := 20, 10, 30
	for _, r := range results {
		if len(r.Asset) > assetW {
			assetW = len(r.Asset)
		}
	}
	_ = confW
	_ = evW

	headerFmt := fmt.Sprintf("%%-%ds  %%-12s  %%-6s  %%-30s  %%s\n", assetW)
	rowFmt := headerFmt

	fmt.Printf(headerFmt, "ASSET", "CONFIDENCE", "SCORE", "FINGERPRINT", "EVIDENCE")
	fmt.Printf(headerFmt, strings.Repeat("-", assetW), "------------", "------", strings.Repeat("-", 30), strings.Repeat("-", 20))
	for _, r := range results {
		fp := strings.TrimSpace(r.HTTPServer)
		if fp == "" && len(r.CNAMEs) > 0 {
			fp = "cname:" + r.CNAMEs[0]
		}
		if fp == "" && len(r.IPs) > 0 {
			fp = "ip:" + r.IPs[0]
		}
		if len(fp) > 30 {
			fp = fp[:27] + "..."
		}
		ev := strings.Join(r.Evidence, "; ")
		if len(ev) > 60 {
			ev = ev[:57] + "..."
		}
		conf := r.Confidence
		if color {
			conf = colorize(conf)
		}
		fmt.Printf(rowFmt, r.Asset, conf, fmt.Sprintf("%d", r.Score), fp, ev)
	}

	// summary
	counts := map[string]int{}
	for _, r := range results {
		counts[r.Confidence]++
	}
	fmt.Println()
	fmt.Printf("summary: %d assets  |  HIGH=%d  MEDIUM=%d  LOW=%d  SUSPICIOUS=%d  UNRESOLVED=%d\n",
		len(results), counts["HIGH"], counts["MEDIUM"], counts["LOW"], counts["SUSPICIOUS"], counts["UNRESOLVED"])
}

func confidenceRank(c string) int {
	switch c {
	case "SUSPICIOUS":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	case "UNRESOLVED":
		return 4
	}
	return 5
}

func colorize(c string) string {
	// ANSI codes: red for SUSPICIOUS, green HIGH, yellow MEDIUM, dim LOW
	switch c {
	case "SUSPICIOUS":
		return "\033[31m" + c + "\033[0m"
	case "HIGH":
		return "\033[32m" + c + "\033[0m"
	case "MEDIUM":
		return "\033[33m" + c + "\033[0m"
	case "LOW":
		return "\033[2m" + c + "\033[0m"
	case "UNRESOLVED":
		return "\033[90m" + c + "\033[0m"
	}
	return c
}

func writeJSON(path string, results []result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}
