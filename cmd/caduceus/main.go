package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/g0ldencybersec/Caduceus/pkg/scrape"
	"github.com/g0ldencybersec/Caduceus/pkg/types"
)

func main() {
	// Original flags
	concurrency := flag.Int("c", 100, "How many goroutines running concurrently")
	timeout := flag.Int("t", 4, "Timeout for TLS handshake")
	ports := flag.String("p", "443", "TLS ports to check for certificates")
	input := flag.String("i", "NONE", "Either IPs & CIDRs separated by commas, or a file with IPs/CIDRs on each line\n\t\tTO USE STDIN, DONT USE THIS FLAG")
	debug := flag.Bool("debug", false, "Add this flag if you want to see failures/timeouts")
	jsonOutput := flag.Bool("j", false, "print cert data as jsonl")
	printWildcards := flag.Bool("wc", false, "print wildcards to stdout")
	help := flag.Bool("h", false, "Show the program usage message")

	// New flags from cadx2.go
	retries := flag.Int("r", 0, "Number of retries for failed connections (default no retry)")
	randomOrder := flag.Bool("rand", false, "Process IPs in random order")
	noEnd := flag.Bool("noEnd", false, "Continue from the start after completing the input file")
	logFile := flag.String("log", "", "Log file to save scan statistics")

	// Additional enhancement flags
	rateLimit := flag.Int("rate", 0, "Rate limit in milliseconds between requests (0 = no limit)")
	expiryDays := flag.Int("expiry", 0, "Only show certificates expiring within N days (0 = show all)")
	filterOrg := flag.String("org", "", "Filter results by organization name (case-insensitive)")
	filterCN := flag.String("cn", "", "Filter results by common name pattern (case-insensitive)")
	exclude := flag.String("exclude", "", "Exclude IPs/CIDRs (comma-separated or file path)")
	domainList := flag.String("dl", "", "Filter by domain list - only show certs matching these domains (comma-separated or file path)")

	flag.Parse()

	if *help {
		printHelp()
		os.Exit(0)
	}

	// Parse ports
	portList := strings.Split(*ports, ",")

	// Handle stdin input
	inputValue := *input
	if inputValue == "NONE" {
		// Read from stdin
		inputValue = readStdin()
		if inputValue == "" {
			fmt.Println("Error: No input provided. Use -i flag or pipe input to stdin.")
			os.Exit(1)
		}
	}

	args := types.ScrapeArgs{
		Concurrency:    *concurrency,
		Ports:          portList,
		Timeout:        *timeout,
		PortList:       *ports,
		Help:           *help,
		Input:          inputValue,
		Debug:          *debug,
		JsonOutput:     *jsonOutput,
		PrintWildcards: *printWildcards,
		PrintStats:     false,

		// New flags from cadx2.go
		Retries:     *retries,
		RandomOrder: *randomOrder,
		NoEnd:       *noEnd,
		LogFile:     *logFile,

		// Additional enhancements
		RateLimit:  *rateLimit,
		ExpiryDays: *expiryDays,
		FilterOrg:  *filterOrg,
		FilterCN:   *filterCN,
		Exclude:    *exclude,
		DomainList: *domainList,
	}

	scrape.RunScrape(args)
}

func readStdin() string {
	var lines []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, ",")
}

func printHelp() {
	fmt.Println(`Caduceus - SSL/TLS Certificate Scanner

USAGE:
  caduceus [options]
  echo "8.8.8.8" | caduceus -j
  caduceus -i targets.txt -c 100 -j

ORIGINAL OPTIONS:
  -i string     Either IPs & CIDRs separated by commas, or a file with IPs/CIDRs
                on each line. TO USE STDIN, DON'T USE THIS FLAG (default "NONE")
  -c int        How many goroutines running concurrently (default 100)
  -t int        Timeout for TLS handshake in seconds (default 4)
  -p string     TLS ports to check for certificates (default "443")
  -j            Print cert data as JSONL
  -wc           Print wildcards to stdout
  -debug        Show failures and timeouts
  -h            Show this help message

NEW OPTIONS (from cadx2.go):
  -r int        Number of retries for failed connections (default 0 = no retry)
  -rand         Process IPs in random order
  -noEnd        Continue from the start after completing the input file
  -log string   Log file to save scan statistics

ADDITIONAL ENHANCEMENTS:
  -rate int     Rate limit in milliseconds between requests (0 = no limit)
  -expiry int   Only show certificates expiring within N days (0 = show all)
  -org string   Filter results by organization name (case-insensitive)
  -cn string    Filter results by common name pattern (case-insensitive)
  -exclude string  Exclude IPs/CIDRs (comma-separated or file path)
  -dl string     Filter by domain list - only show certs matching these domains

EXAMPLES:
  # Basic scan with JSON output
  echo "8.8.8.8" | caduceus -j

  # Scan with retries and logging
  caduceus -i targets.txt -r 3 -log scan.log

  # Random order with rate limiting
  caduceus -i targets.txt -rand -rate 100

  # Find expiring certificates
  caduceus -i targets.txt -expiry 30 -j

  # Filter by organization
  caduceus -i targets.txt -org "google" -j

  # Continuous monitoring mode
  caduceus -i targets.txt -noEnd -log monitor.log

  # Filter by domain list
  caduceus -i targets.txt -dl domains.txt -j
  caduceus -i targets.txt -dl "example.com,test.com" -j
`)
}
