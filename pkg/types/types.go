package types

import "net"

// Scraper Arg types
type ScrapeArgs struct {
	Concurrency    int
	Ports          []string
	Timeout        int
	PortList       string
	Help           bool
	Input          string
	Debug          bool
	JsonOutput     bool
	PrintWildcards bool
	PrintStats     bool

	// New fields from cadx2.go
	Retries     int    // -r: Number of retries for failed connections
	RandomOrder bool   // -rand: Process IPs in random order
	NoEnd       bool   // -noEnd: Continue from start after completing
	LogFile     string // -log: Log file for scan statistics

	// Additional enhancements
	RateLimit  int    // -rate: Delay in ms between requests
	ExpiryDays int    // -expiry: Alert on certs expiring within N days
	FilterOrg  string // -org: Filter by organization name
	FilterCN   string // -cn: Filter by common name pattern
	Exclude    string // -exclude: Exclude IPs/CIDRs (comma-separated or file)
	DomainList string // -dl: Filter by domain list (comma-separated or file)
}

// Result Types
type CertificateInfo struct {
	OriginIP         string   `json:"originip"`
	Organization     []string `json:"org"`
	OrganizationUnit []string `json:"orgunit"`
	CommonName       string   `json:"commonName"`
	SAN              []string `json:"san"`
	Domains          []string `json:"domains"`
	Emails           []string `json:"emails"`
	IPAddrs          []net.IP `json:"ips"`

	// Extended info from cadx2.go
	SubjectDN          string `json:"subject_dn"` // Full Distinguished Name
	IssuerDN           string `json:"issuer_dn"`  // Full Distinguished Name
	NotBefore          string `json:"not_before"`
	NotAfter           string `json:"not_after"`
	SerialNumber       string `json:"serial_number"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
	ExpiringWithinDays int    `json:"expiring_within_days,omitempty"`
}

type Result struct {
	IP          string
	Hit         bool
	Timeout     bool
	Error       error
	Certificate *CertificateInfo
	Retries     int // Track how many retries were needed
}

// Stats Types
type Stats struct {
	hits   int
	misses int
	total  int
}
