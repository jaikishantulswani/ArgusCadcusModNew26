package workers

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/g0ldencybersec/Caduceus/pkg/types"
	"github.com/g0ldencybersec/Caduceus/pkg/utils"
)

// Worker Types
type Worker struct {
	dialer     *net.Dialer
	input      <-chan string
	results    chan<- types.Result
	retries    int            // NEW: configurable retries
	rateMs     int            // NEW: rate limiting
	exclusions map[string]bool // NEW: exclusion list
	stats      *utils.ScanStats // NEW: stats tracking
}

type WorkerPool struct {
	workers    []*Worker
	input      chan string
	results    chan types.Result
	dialer     *net.Dialer
	wg         sync.WaitGroup
	retries    int
	rateMs     int
	exclusions map[string]bool
	stats      *utils.ScanStats
}

func NewWorker(dialer *net.Dialer, input <-chan string, results chan<- types.Result, retries int, rateMs int, exclusions map[string]bool, stats *utils.ScanStats) *Worker {
	return &Worker{
		dialer:     dialer,
		input:      input,
		results:    results,
		retries:    retries,
		rateMs:     rateMs,
		exclusions: exclusions,
		stats:      stats,
	}
}

func (w *Worker) run() {
	for ip := range w.input {
		// Rate limiting
		if w.rateMs > 0 {
			time.Sleep(time.Duration(w.rateMs) * time.Millisecond)
		}

		// Check exclusions
		if utils.IsExcluded(ip, w.exclusions) {
			continue
		}

		var cert *types.CertificateInfo
		var err error
		var retryCount int

		// Retry loop
		for attempt := 0; attempt <= w.retries; attempt++ {
			cert, err = getCertWithExtendedInfo(ip, w.dialer)
			if err == nil {
				break // Success
			}
			// Only count as a retry if this isn't the first attempt
			if attempt > 0 {
				retryCount++
			}
			if attempt < w.retries {
				time.Sleep(time.Second) // Wait before retrying
			}
		}

		// Track retries in stats
		if w.stats != nil && retryCount > 0 {
			w.stats.AddRetries(retryCount)
		}

		if err != nil {
			netErr, ok := err.(net.Error)
			if ok && netErr.Timeout() {
				if w.stats != nil {
					w.stats.IncrTimeout()
				}
				w.results <- types.Result{IP: ip, Hit: false, Timeout: true, Retries: retryCount}
			} else {
				if w.stats != nil {
					w.stats.IncrFailure()
				}
				w.results <- types.Result{IP: ip, Error: err, Hit: false, Timeout: false, Retries: retryCount}
			}
			continue
		}

		if w.stats != nil {
			w.stats.IncrSuccess()
		}

		w.results <- types.Result{IP: ip, Hit: true, Certificate: cert, Timeout: false, Retries: retryCount}
	}
}

// getCertWithExtendedInfo fetches certificate with all extended fields
func getCertWithExtendedInfo(ip string, dialer *net.Dialer) (*types.CertificateInfo, error) {
	cert, err := utils.GetSSLCert(ip, dialer)
	if err != nil {
		return nil, err
	}

	certInfo := &types.CertificateInfo{
		OriginIP:           ip,
		Organization:       cert.Subject.Organization,
		OrganizationUnit:   cert.Subject.OrganizationalUnit,
		CommonName:         cert.Subject.CommonName,
		SAN:                cert.DNSNames,
		Domains:            append([]string{cert.Subject.CommonName}, cert.DNSNames...),
		Emails:             cert.EmailAddresses,
		IPAddrs:            cert.IPAddresses,
		// Extended info from cadx2.go
		SubjectDN:          cert.Subject.String(),
		IssuerDN:           cert.Issuer.String(),
		NotBefore:          cert.NotBefore.Format(time.RFC3339),
		NotAfter:           cert.NotAfter.Format(time.RFC3339),
		SerialNumber:       cert.SerialNumber.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
	}

	// Calculate expiry in days
	daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)
	if daysUntilExpiry >= 0 {
		certInfo.ExpiringWithinDays = daysUntilExpiry
	}

	return certInfo, nil
}

func NewWorkerPool(size int, dialer *net.Dialer, input chan string, results chan types.Result, retries int, rateMs int, exclusions map[string]bool, stats *utils.ScanStats) *WorkerPool {
	wp := &WorkerPool{
		workers:    make([]*Worker, size),
		input:      input,
		results:    results,
		dialer:     dialer,
		wg:         sync.WaitGroup{},
		retries:    retries,
		rateMs:     rateMs,
		exclusions: exclusions,
		stats:      stats,
	}
	for i := range wp.workers {
		wp.workers[i] = NewWorker(wp.dialer, wp.input, wp.results, retries, rateMs, exclusions, stats)
	}
	return wp
}

func (wp *WorkerPool) Start() {
	for _, worker := range wp.workers {
		wp.wg.Add(1)
		go func(w *Worker) {
			defer wp.wg.Done()
			w.run()
		}(worker)
	}
}

func (wp *WorkerPool) Stop() {
	wp.wg.Wait()
	close(wp.results)
}

// Result Workers
type ResultsWorker struct {
	resultInput   <-chan types.Result
	outputChannel chan<- string
}

type ResultsWorkerPool struct {
	workers       []*ResultsWorker
	resultInput   chan types.Result
	outputChannel chan string
	wg            sync.WaitGroup
}

func NewResultsWorker(resultInput <-chan types.Result, outputChannel chan<- string) *ResultsWorker {
	return &ResultsWorker{
		resultInput:   resultInput,
		outputChannel: outputChannel,
	}
}

func (rw *ResultsWorker) Run(args types.ScrapeArgs, allowedDomains map[string]bool) {
	for result := range rw.resultInput {
		if result.Hit {
			// Apply filters
			if args.FilterOrg != "" && !utils.MatchesOrgFilter(result.Certificate.Organization, args.FilterOrg) {
				continue
			}
			if args.FilterCN != "" && !utils.MatchesCNFilter(result.Certificate.CommonName, args.FilterCN) {
				continue
			}

			// Check expiry alert
			if args.ExpiryDays > 0 && result.Certificate.ExpiringWithinDays > args.ExpiryDays {
				continue // Skip if not expiring within threshold
			}

			// Check domain list filter
			if !utils.MatchesDomainList(result.Certificate.Domains, allowedDomains) {
				continue // Skip if no domains match the allowed list
			}

			if args.JsonOutput {
				outputJSON, _ := json.Marshal(result.Certificate)
				rw.outputChannel <- string(outputJSON)
			} else {
				// User requested format: IP Subject Issuer DNSNames(comma-separated) NotBefore NotAfter SerialNumber SigAlg PubKeyAlg
				// Strip port from OriginIP for display
				host := result.Certificate.OriginIP
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}

				dnsNames := strings.Join(result.Certificate.SAN, ",")
				output := fmt.Sprintf("%s %s %s %s %s %s %s %s %s",
					host,
					result.Certificate.SubjectDN,
					result.Certificate.IssuerDN,
					dnsNames,
					result.Certificate.NotBefore,
					result.Certificate.NotAfter,
					result.Certificate.SerialNumber,
					result.Certificate.SignatureAlgorithm,
					result.Certificate.PublicKeyAlgorithm,
				)
				rw.outputChannel <- output
			}
		} else if args.Debug {
			if result.Timeout {
				msg := fmt.Sprintf("Timed Out. No SSL certificate found for %s", result.IP)
				if result.Retries > 0 {
					msg += fmt.Sprintf(" (after %d retries)", result.Retries)
				}
				rw.outputChannel <- msg
			}
			if result.Error != nil {
				msg := fmt.Sprintf("Failed to get SSL certificate from %s: %v", result.IP, result.Error)
				if result.Retries > 0 {
					msg += fmt.Sprintf(" (after %d retries)", result.Retries)
				}
				rw.outputChannel <- msg
			}
		}
	}
}

func NewResultWorkerPool(size int, resultInput chan types.Result, outputChannel chan string) *ResultsWorkerPool {
	rwp := &ResultsWorkerPool{
		workers:       make([]*ResultsWorker, size),
		resultInput:   resultInput,
		outputChannel: outputChannel,
		wg:            sync.WaitGroup{},
	}
	for i := range rwp.workers {
		rwp.workers[i] = NewResultsWorker(rwp.resultInput, rwp.outputChannel)
	}
	return rwp
}

func (rwp *ResultsWorkerPool) Start(args types.ScrapeArgs, allowedDomains map[string]bool) {
	for _, worker := range rwp.workers {
		rwp.wg.Add(1)
		go func(rw *ResultsWorker) {
			defer rwp.wg.Done()
			rw.Run(args, allowedDomains)
		}(worker)
	}
}

func (rwp *ResultsWorkerPool) Stop() {
	rwp.wg.Wait()
	close(rwp.outputChannel)
}

