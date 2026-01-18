package scrape

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/g0ldencybersec/Caduceus/pkg/types"
	"github.com/g0ldencybersec/Caduceus/pkg/utils"
	"github.com/g0ldencybersec/Caduceus/pkg/workers"
)

func RunScrape(args types.ScrapeArgs) {
	dialer := &net.Dialer{
		Timeout: time.Duration(args.Timeout) * time.Second,
	}

	// Load exclusions once
	exclusions := utils.LoadExclusions(args.Exclude)

	// Load domain list filter once
	allowedDomains := utils.LoadDomainList(args.DomainList)

	// Main loop for noEnd functionality
	for {
		// Initialize stats for this run
		stats := utils.NewScanStats(args.LogFile)

		// Log start if logging enabled
		if args.LogFile != "" {
			utils.SaveLog(args.LogFile, stats, "Scan started.")
		}

		// Calculate total targets for stats (crucial for progress logging in non-random mode)
		if !args.RandomOrder {
			targetCount := utils.CountTargets(args.Input)
			totalScans := targetCount * len(args.Ports)
			stats.SetTotal(totalScans)
		}

		inputChannel := make(chan string)
		resultChannel := make(chan types.Result)
		outputChannel := make(chan string, args.Concurrency/10+1)

		// Create and start the worker pool with new parameters
		workerPool := workers.NewWorkerPool(
			args.Concurrency,
			dialer,
			inputChannel,
			resultChannel,
			args.Retries,
			args.RateLimit,
			exclusions,
			stats,
		)
		workerPool.Start()

		// Create and start the results worker pool
		resultsWorkerSize := args.Concurrency / 100
		if resultsWorkerSize < 1 {
			resultsWorkerSize = 1
		}
		resultsWorkerPool := workers.NewResultWorkerPool(resultsWorkerSize, resultChannel, outputChannel)
		resultsWorkerPool.Start(args, allowedDomains)

		// Handle input feeding
		go func() {
			if args.RandomOrder {
				// Collect all targets first, then shuffle
				targets := utils.CollectTargets(args.Ports, args.Input)
				stats.SetTotal(len(targets))
				utils.ShuffleTargets(targets)
				utils.FeedTargets(inputChannel, targets)
			} else {
				utils.IntakeFunction(inputChannel, args.Ports, args.Input)
			}
			close(inputChannel)
		}()

		// Handle outputs
		var outputWg sync.WaitGroup
		outputWg.Add(1)
		go func() {
			defer outputWg.Done()
			for output := range outputChannel {
				fmt.Println(output)
			}
		}()

		workerPool.Stop()
		resultsWorkerPool.Stop()
		outputWg.Wait()

		// Finalize stats and save log
		stats.Finish()
		if args.LogFile != "" {
			utils.SaveLog(args.LogFile, stats, "Scan completed.")
		}

		// Break if noEnd is false
		if !args.NoEnd {
			break
		}

		// Small delay before restarting if noEnd is true
		if args.Debug {
			fmt.Println("[noEnd] Restarting scan from beginning...")
		}
		time.Sleep(time.Second)
	}
}

