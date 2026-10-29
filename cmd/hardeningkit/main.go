package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/YOUR_USERNAME/hardeningkit/internal/audit"
)

const version = "0.1.0"

func main() {
	jsonPath := flag.String("json", "", "write report as JSON")
	noColor := flag.Bool("no-color", false, "disable ANSI colors")
	timeout := flag.Duration("timeout", 3*time.Second, "best-effort audit time budget")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion { fmt.Println("HardeningKit", version); return }

	color := !*noColor && os.Getenv("NO_COLOR") == "" && terminal()
	start := time.Now()
	report := audit.Run(*timeout)
	report.Duration = time.Since(start).Round(time.Millisecond).String()
	render(report, color)

	if *jsonPath != "" {
		if err := os.MkdirAll(dirOf(*jsonPath), 0755); err != nil { fatal(err) }
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil { fatal(err) }
		if err = os.WriteFile(*jsonPath, append(b, '\n'), 0644); err != nil { fatal(err) }
		fmt.Println("\nJSON report saved:", *jsonPath)
	}
	if report.Critical > 0 || report.High > 0 { os.Exit(2) }
}
func fatal(err error) { fmt.Fprintln(os.Stderr, "error:", err); os.Exit(1) }
func terminal() bool { fi, err := os.Stdout.Stat(); return err == nil && fi.Mode()&os.ModeCharDevice != 0 }
func dirOf(p string) string { i := strings.LastIndexAny(p, `/\`); if i < 0 { return "." }; if i == 0 { return p[:1] }; return p[:i] }
func paint(s, code string, on bool) string { if !on { return s }; return "\033[" + code + "m" + s + "\033[0m" }

func render(r audit.Report, color bool) {
	fmt.Println(paint("╭──────────────────────────────────────────────────────────────╮", "36", color))
	fmt.Println(paint("│  HARDENINGKIT · LINUX SECURITY BASELINE SCANNER              │", "1;36", color))
	fmt.Println(paint("╰──────────────────────────────────────────────────────────────╯", "36", color))
	fmt.Printf("  Host: %-24s OS: %s/%s\n", r.Hostname, r.OS, r.Arch)
	fmt.Printf("  Kernel: %-22s Runtime: %s\n", r.Kernel, r.Duration)
	fmt.Printf("  Checks: %-5d Findings: %d\n\n", r.ChecksRun, len(r.Findings))
	for _, f := range r.Findings {
		code := "36"
		switch f.Severity { case "CRITICAL", "HIGH": code = "31;1"; case "MEDIUM": code = "33"; case "LOW": code = "34" }
		fmt.Printf("  %s %-8s %s\n", paint("●", code, color), paint(f.Severity, code, color), f.Title)
		fmt.Printf("      %s\n", f.Detail)
		if f.Remediation != "" { fmt.Printf("      Fix: %s\n", f.Remediation) }
	}
	fmt.Printf("\n  Summary: %d critical · %d high · %d medium · %d low\n", r.Critical, r.High, r.Medium, r.Low)
	fmt.Println(paint("  Read-only audit. Findings are signals, not a certification.", "2", color))
}
