package utils

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/rand"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var domainRegex = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

func GetSSLCert(ip string, dialer *net.Dialer) (*x509.Certificate, error) {
	conn, err := tls.DialWithDialer(dialer, "tcp", ip, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	return cert, nil
}

// IPsFromCIDR generates a slice of IP strings from the given CIDR
func IPsFromCIDR(cidr string, chanInput chan string, ports []string) error {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		for _, port := range ports {
			chanInput <- ip.String() + ":" + port
		}
	}

	return nil
}

// inc increments an IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func IntakeFunction(chanInput chan string, ports []string, input string) {
	if _, err := os.Stat(input); err == nil {
		readFile, err := os.Open(input)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fileScanner := bufio.NewScanner(readFile)

		fileScanner.Split(bufio.ScanLines)

		for fileScanner.Scan() {
			line := fileScanner.Text()
			processInput(line, chanInput, ports)
		}
		readFile.Close()

	} else {
		for _, argItem := range strings.Split(input, ",") {
			processInput(argItem, chanInput, ports)
		}
	}
}

func isCIDR(value string) bool {
	return strings.Contains(value, `/`)
}

func isHostPort(value string) bool {
	return strings.Contains(value, `:`)
}

func processInput(argItem string, chanInput chan string, ports []string) {
	argItem = strings.TrimSpace(argItem)
	if isHostPort(argItem) {
		chanInput <- argItem
	} else if isCIDR(argItem) {
		err := IPsFromCIDR(argItem, chanInput, ports)
		if err != nil {
			panic("unable to parse CIDR" + argItem)
		}
	} else {
		for _, port := range ports {
			chanInput <- argItem + ":" + port
		}
	}
}

func IsValidDomain(domain string) bool {
	return domainRegex.MatchString(domain)
}

func IsWilcard(domain string) bool {
	replaced := strings.Replace(domain, "*.", "", -1)
	return (strings.Contains(domain, "*") && IsValidDomain(replaced))
}

// ============ NEW FUNCTIONS FOR ENHANCED FEATURES ============

// CollectTargets collects all targets into a slice (for random shuffling)
func CollectTargets(ports []string, input string) []string {
	var targets []string

	if _, err := os.Stat(input); err == nil {
		readFile, err := os.Open(input)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		defer readFile.Close()

		fileScanner := bufio.NewScanner(readFile)
		fileScanner.Split(bufio.ScanLines)

		for fileScanner.Scan() {
			line := strings.TrimSpace(fileScanner.Text())
			if line == "" {
				continue
			}
			collected := collectFromInput(line, ports)
			targets = append(targets, collected...)
		}
	} else {
		for _, argItem := range strings.Split(input, ",") {
			collected := collectFromInput(argItem, ports)
			targets = append(targets, collected...)
		}
	}

	return targets
}

func collectFromInput(argItem string, ports []string) []string {
	var targets []string
	argItem = strings.TrimSpace(argItem)

	if isHostPort(argItem) {
		targets = append(targets, argItem)
	} else if isCIDR(argItem) {
		ips := ipsFromCIDRToSlice(argItem, ports)
		targets = append(targets, ips...)
	} else {
		for _, port := range ports {
			targets = append(targets, argItem+":"+port)
		}
	}
	return targets
}

func ipsFromCIDRToSlice(cidr string, ports []string) []string {
	var ips []string
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ips
	}

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		for _, port := range ports {
			ips = append(ips, ip.String()+":"+port)
		}
	}
	return ips
}

// ShuffleTargets randomizes the order of targets
func ShuffleTargets(targets []string) {
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(targets), func(i, j int) {
		targets[i], targets[j] = targets[j], targets[i]
	})
}

// FeedTargets sends targets to the input channel
func FeedTargets(chanInput chan string, targets []string) {
	for _, target := range targets {
		chanInput <- target
	}
}

// LoadExclusions loads exclusion IPs/CIDRs from input (file or comma-separated)
func LoadExclusions(input string) map[string]bool {
	exclusions := make(map[string]bool)
	if input == "" {
		return exclusions
	}

	var items []string
	if _, err := os.Stat(input); err == nil {
		readFile, err := os.Open(input)
		if err != nil {
			return exclusions
		}
		defer readFile.Close()

		scanner := bufio.NewScanner(readFile)
		for scanner.Scan() {
			items = append(items, strings.TrimSpace(scanner.Text()))
		}
	} else {
		items = strings.Split(input, ",")
	}

	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if isCIDR(item) {
			// Expand CIDR into individual IPs
			ip, ipnet, err := net.ParseCIDR(item)
			if err != nil {
				continue
			}
			for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
				exclusions[ip.String()] = true
			}
		} else {
			exclusions[item] = true
		}
	}
	return exclusions
}

// IsExcluded checks if an IP is in the exclusion list
func IsExcluded(ip string, exclusions map[string]bool) bool {
	// Extract just the IP part (without port)
	host := ip
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		host = ip[:idx]
	}
	return exclusions[host]
}

// ============ LOGGING FUNCTIONS ============

type ScanStats struct {
	TotalIPs      int
	CurrentIndex  int
	Successes     int
	Failures      int
	Timeouts      int
	TotalRetries  int
	StartTime     time.Time
	EndTime       time.Time
	mu            sync.Mutex
	LogFile       string
}

func NewScanStats(logFile string) *ScanStats {
	return &ScanStats{
		StartTime: time.Now(),
		LogFile:   logFile,
	}
}

func (s *ScanStats) checkAndLog() {
	if s.LogFile == "" {
		return
	}
	// Match cadx2.go logic: log every 502 iterations
	if s.CurrentIndex%502 == 0 {
		msg := fmt.Sprintf("Current Scan on IP number: %d/%d", s.CurrentIndex, s.TotalIPs)
		SaveLog(s.LogFile, nil, msg)
	}
}

func (s *ScanStats) IncrSuccess() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Successes++
	s.CurrentIndex++
	s.checkAndLog()
}

func (s *ScanStats) IncrFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Failures++
	s.CurrentIndex++
	s.checkAndLog()
}

func (s *ScanStats) IncrTimeout() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Timeouts++
	s.CurrentIndex++
	s.checkAndLog()
}

func (s *ScanStats) AddRetries(count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalRetries += count
}

func (s *ScanStats) SetTotal(total int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalIPs = total
}

func (s *ScanStats) Finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.EndTime = time.Now()
}

// SaveLog saves scan statistics to a log file
func SaveLog(filePath string, stats *ScanStats, message string) error {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	timestamp := time.Now().Format("2006-01-02T15:04:05.000Z")

	var logContent string
	if message == "Scan completed." {
		duration := stats.EndTime.Sub(stats.StartTime)
		logContent = fmt.Sprintf("%s Scan completed. Stats: Total IPs: %d, Successful: %d, Failures: %d, Timeouts: %d, Retries: %d, Duration: %s\n",
			timestamp, stats.TotalIPs, stats.Successes, stats.Failures, stats.Timeouts, stats.TotalRetries, duration.Round(time.Second))
	} else {
		logContent = fmt.Sprintf("%s %s\n", timestamp, message)
	}

	_, err = file.WriteString(logContent)
	return err
}

// CountTargets calculates the total number of targets from input
func CountTargets(input string) int {
	total := 0
	if _, err := os.Stat(input); err == nil {
		file, err := os.Open(input)
		if err != nil {
			return 0
		}
		defer file.Close()

		limit := 1024 * 1024 // Limit line length to prevent issues with massive single lines
		buf := make([]byte, limit)
		scanner := bufio.NewScanner(file)
		scanner.Buffer(buf, limit)

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			// Handle comma-separated on a line too? standard Caduceus input is one per line or comma-sep arg
			// If file line contains comma, Caduceus processInput splits it? No, processInput takes `argItem`.
			// IntakeFunction: for fileScanner.Scan() { processInput(line) }
			// processInput handles CIDR or HostPort. It doesn't split commas!
			// Wait, IntakeFunction splits by comma ONLY if it's NOT a file.
			
			if isCIDR(line) {
				total += countIPsInCIDR(line)
			} else {
				total++
			}
		}
	} else {
		for _, argItem := range strings.Split(input, ",") {
			argItem = strings.TrimSpace(argItem)
			if argItem == "" {
				continue
			}
			if isCIDR(argItem) {
				total += countIPsInCIDR(argItem)
			} else {
				total++
			}
		}
	}
	// Multiply by number of ports? Caduceus scans each IP on ALL ports.
	// YES! Total scans = Total IPs * Total Ports.
	// But current CountTargets returns just target count (IPs/Networks).
	// Calling code needs to multiply by len(ports).
	return total
}

func countIPsInCIDR(cidr string) int {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0
	}
	ones, bits := ipnet.Mask.Size()
	return 1 << (uint(bits) - uint(ones))
}

// LogProgress logs current progress to file (Deprecated/Unused - kept for API compatibility if needed, but safe to remove)
// Removing it as requested logic is now inside ScanStats


// ============ FILTER FUNCTIONS ============

// MatchesFilter checks if certificate matches filter criteria
func MatchesOrgFilter(orgs []string, pattern string) bool {
	if pattern == "" {
		return true
	}
	pattern = strings.ToLower(pattern)
	for _, org := range orgs {
		if strings.Contains(strings.ToLower(org), pattern) {
			return true
		}
	}
	return false
}

// MatchesCNFilter checks if common name matches filter pattern
func MatchesCNFilter(cn string, pattern string) bool {
	if pattern == "" {
		return true
	}
	return strings.Contains(strings.ToLower(cn), strings.ToLower(pattern))
}

// LoadDomainList loads allowed domains from input (file or comma-separated)
func LoadDomainList(input string) map[string]bool {
	domains := make(map[string]bool)
	if input == "" {
		return domains
	}

	var items []string
	if _, err := os.Stat(input); err == nil {
		readFile, err := os.Open(input)
		if err != nil {
			return domains
		}
		defer readFile.Close()

		scanner := bufio.NewScanner(readFile)
		for scanner.Scan() {
			items = append(items, strings.TrimSpace(scanner.Text()))
		}
	} else {
		items = strings.Split(input, ",")
	}

	for _, item := range items {
		item = strings.TrimSpace(strings.ToLower(item))
		if item == "" {
			continue
		}
		// Handle wildcard domains (e.g., *.example.com -> example.com)
		item = strings.TrimPrefix(item, "*.")
		domains[item] = true
	}
	return domains
}

// MatchesDomainList checks if any certificate domain matches the allowed domain list
func MatchesDomainList(certDomains []string, allowedDomains map[string]bool) bool {
	if len(allowedDomains) == 0 {
		return true // No filter applied
	}

	for _, domain := range certDomains {
		domain = strings.ToLower(domain)
		// Remove wildcard prefix for matching
		domain = strings.TrimPrefix(domain, "*.")

		// Direct match
		if allowedDomains[domain] {
			return true
		}

		// Check if domain is a subdomain of any allowed domain
		for allowed := range allowedDomains {
			if strings.HasSuffix(domain, "."+allowed) || domain == allowed {
				return true
			}
		}
	}
	return false
}
