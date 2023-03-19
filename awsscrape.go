package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

type IPRange struct {
	Prefixes []struct {
		IPPrefix string `json:"ip_prefix"`
	} `json:"prefixes"`
}

const (
	defaultTimeout = 10 * time.Second
)

var (
	logger = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds)

	// Flags
	keywordFlag = flag.String("keyword", "", "Keyword to search in SSL certificates")
	timeoutFlag = flag.Duration("timeout", defaultTimeout, "Timeout for network operations")
	threadsFlag = flag.Int("threads", 1, "Number of concurrent threads to use")
)

type CheckIPRangeError struct {
	IPRange string
	Err     error
}

func (e CheckIPRangeError) Error() string {
	return fmt.Sprintf("error checking IP range %s: %v", e.IPRange, e.Err)
}

func main() {
	flag.Parse()

	if *keywordFlag == "" {
		fmt.Printf("Usage: %s -keyword=<your_keyword>\n", os.Args[0])
		os.Exit(1)
	}

	ipRanges, err := getIPRanges()
	if err != nil {
		logger.Fatalf("Error fetching IP ranges: %v", err)
	}

	ipAddresses := &sync.Map{}
	eg := &errgroup.Group{}
	ctx, cancel := context.WithTimeout(context.Background(), *timeoutFlag)
	defer cancel()

	threadCount := *threadsFlag
	if threadCount <= 0 {
		threadCount = 1
	}
	rangeCount := len(ipRanges.Prefixes)
	rangesPerThread := (rangeCount + threadCount - 1) / threadCount

	for i := 0; i < rangeCount; i += rangesPerThread {
		start := i
		end := i + rangesPerThread
		if end > rangeCount {
			end = rangeCount
		}
		eg.Go(func() error {
			for j := start; j < end; j++ {
				err := checkIPRange(ctx, ipRanges.Prefixes[j].IPPrefix, *keywordFlag, ipAddresses)
				if err != nil {
					return CheckIPRangeError{ipRanges.Prefixes[j].IPPrefix, err}
				}
			}
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		logger.Fatalf("%v", err)
	}

	ipAddresses.Range(func(key, value interface{}) bool {
		logger.Printf("Keyword found in SSL certificate for IP: %s\n", key)
		return true
	})
}

func getIPRanges() (*IPRange, error) {
	resp, err := http.Get("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		return nil, fmt.Errorf("error fetching IP ranges: %w", err)
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading IP ranges response body: %w", err)
	}

	ipRanges := &IPRange{}
	if err := json.Unmarshal(data, ipRanges); err != nil {
		return nil, fmt.Errorf("error unmarshaling IP ranges: %w", err)
	}

	return ipRanges, nil
}

func checkIPRange(ctx context.Context, ipRange, keyword string, ipAddresses *sync.Map) error {
	ip, _,
