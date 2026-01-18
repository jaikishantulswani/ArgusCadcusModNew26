package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type CertificateDetails struct {
	OriginIP           string   `json:"originip"`
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	DNSNames           []string `json:"dns_names"`
	NotBefore          string   `json:"not_before"`
	NotAfter           string   `json:"not_after"`
	SerialNumber       string   `json:"serial_number"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	PublicKeyAlgorithm string   `json:"public_key_algorithm"`
}

var (
	inputFile    = flag.String("i", "", "Input file containing IPs/CIDRs or ip:port pairs")
	concurrency  = flag.Int("c", 10, "Number of concurrent workers")
	retries      = flag.Int("r", 0, "Number of retries for failed connections")
	timeout      = flag.Duration("t", 5*time.Second, "Timeout for each connection")
	jsonOutput   = flag.Bool("j", false, "Output in JSON format")
	debug        = flag.Bool("debug", false, "Print debug information")
	logFile      = flag.String("log", "", "Log file to save scan statistics")
	noEnd        = flag.Bool("noEnd", false, "Continue from the start after completing the input file")
	random       = flag.Bool("rand", false, "Process IPs in random order")
)

var (
	totalIPs       int
	totalSuccess   int
	totalFailures  int
	totalRetries   int
	currentIPIndex int
	logMutex       sync.Mutex
)

func main() {
	flag.Parse()

	for {
		var targets []string
		if *inputFile != "" {
			targets = readTargetsFromFile(*inputFile)
		} else {
			targets = readTargetsFromStdin()
		}

		if *random {
			rand.Seed(time.Now().UnixNano())
			rand.Shuffle(len(targets), func(i, j int) {
				targets[i], targets[j] = targets[j], targets[i]
			})
		}

		totalIPs = len(targets)

		workChan := make(chan string, len(targets))
		resultsChan := make(chan CertificateDetails, len(targets))

		var wg sync.WaitGroup
		for i := 0; i < *concurrency; i++ {
			wg.Add(1)
			go worker(workChan, resultsChan, &wg)
		}

		// Feed targets to the work channel concurrently
		go func() {
			for _, target := range targets {
				workChan <- target
			}
			close(workChan)
		}()

		// Process results in real-time
		go func() {
			for result := range resultsChan {
				if *jsonOutput {
					jsonData, _ := json.Marshal(result)
					fmt.Println(string(jsonData))
				} else {
					fmt.Printf("Origin IP: %s\nSubject: %s\nIssuer: %s\nDNS Names: %v\nNot Before: %s\nNot After: %s\nSerial Number: %s\nSignature Algorithm: %s\nPublic Key Algorithm: %s\n\n",
						result.OriginIP, result.Subject, result.Issuer, result.DNSNames, result.NotBefore, result.NotAfter, result.SerialNumber, result.SignatureAlgorithm, result.PublicKeyAlgorithm)
				}
			}
		}()

		wg.Wait()
		close(resultsChan)

		// Save log if log file is specified
		if *logFile != "" {
			saveLog("Scan completed.")
		}

		if !*noEnd {
			break
		}
	}
}

func readTargetsFromFile(filePath string) []string {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "/") {
			expandedIPs := expandCIDR(line)
			targets = append(targets, expandedIPs...)
		} else {
			targets = append(targets, line)
		}
	}
	return targets
}

func readTargetsFromStdin() []string {
	var targets []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "/") {
			expandedIPs := expandCIDR(line)
			targets = append(targets, expandedIPs...)
		} else {
			targets = append(targets, line)
		}
	}
	return targets
}

func expandCIDR(cidr string) []string {
	ips := []string{}
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Printf("Error parsing CIDR %s: %v\n", cidr, err)
		return ips
	}

	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// Handle cases where the CIDR block is too small to remove network and broadcast addresses
	if len(ips) <= 2 {
		if *debug {
			fmt.Printf("CIDR block %s is too small to remove network and broadcast addresses\n", cidr)
		}
		return ips
	}

	// Remove network address and broadcast address
	return ips[1 : len(ips)-1]
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func worker(workChan <-chan string, resultsChan chan<- CertificateDetails, wg *sync.WaitGroup) {
	defer wg.Done()
	for target := range workChan {
		host, port := parseTarget(target)

		// Update current IP being processed
		logMutex.Lock()
		currentIPIndex++
		if *logFile != "" && currentIPIndex%502 == 0 {
			saveLog(fmt.Sprintf("Current Scan on IP number: %d/%d", currentIPIndex, totalIPs))
		}
		logMutex.Unlock()

		var certDetails CertificateDetails
		var err error
		retryCount := 0

		// Retry logic
		for attempt := 0; attempt <= *retries; attempt++ {
			certDetails, err = fetchCertificate(host, port)
			if err == nil {
				certDetails.OriginIP = host // Set the OriginIP field
				break // Success, exit retry loop
			}
			retryCount++
			if *debug {
				fmt.Printf("Attempt %d: Error fetching certificate from %s:%s: %v\n", attempt+1, host, port, err)
			}
			if attempt < *retries {
				time.Sleep(time.Second) // Wait before retrying
			}
		}

		logMutex.Lock()
		if err == nil {
			totalSuccess++
		} else {
			totalFailures++
		}
		totalRetries += retryCount
		logMutex.Unlock()

		if err != nil {
			if *debug {
				fmt.Printf("Failed to fetch certificate from %s:%s after %d retries: %v\n", host, port, *retries, err)
			}
			continue
		}

		resultsChan <- certDetails
	}
}

func parseTarget(target string) (string, string) {
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		return parts[0], parts[1]
	}
	return target, "443"
}

func fetchCertificate(host, port string) (CertificateDetails, error) {
	var certDetails CertificateDetails
	conn, err := tls.DialWithDialer(&net.Dialer{
		Timeout: *timeout,
	}, "tcp", net.JoinHostPort(host, port), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return certDetails, err
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	certDetails.Subject = cert.Subject.String()
	certDetails.Issuer = cert.Issuer.String()
	certDetails.DNSNames = cert.DNSNames
	certDetails.NotBefore = cert.NotBefore.Format(time.RFC3339)
	certDetails.NotAfter = cert.NotAfter.Format(time.RFC3339)
	certDetails.SerialNumber = cert.SerialNumber.String()
	certDetails.SignatureAlgorithm = cert.SignatureAlgorithm.String()
	certDetails.PublicKeyAlgorithm = cert.PublicKeyAlgorithm.String()

	return certDetails, nil
}

func saveLog(message string) {
	file, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening log file: %v\n", err)
		return
	}
	defer file.Close()

	timestamp := time.Now().Format("2006-01-02T15:04:05.000Z")
	logContent := fmt.Sprintf("%s %s\n", timestamp, message)

	if message == "Scan completed." {
		logContent = fmt.Sprintf("%s Scan completed. Stats: Total IPs: %d, Successful: %d, Failures: %d, Retries: %d, Total Scanned: %d\n",
			timestamp, totalIPs, totalSuccess, totalFailures, totalRetries, currentIPIndex)
	}

	_, err = file.WriteString(logContent)
	if err != nil {
		fmt.Printf("Error writing to log file: %v\n", err)
	}
}
