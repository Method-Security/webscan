// Package fuzz holds the data structures and logic necessary to perform web application fuzzing for the `webscan fuzz`
// command
package fuzz

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
)

const (
	TerminalClearLine = "\r\x1b[2K"
	AnsiClear         = "\x1b[0m"
	AnsiRed           = "\x1b[31m"
)

// CustomOutput is a custom output implementation for ffuf. This implementation is used to customize the output of the
// ffuf tool to provide easier data integration and automation capabilies within the webscan tool.
type CustomOutput struct {
	config         *ffuf.Config
	fuzzkeywords   []string
	Results        []ffuf.Result
	CurrentResults []ffuf.Result
}

// NewCustomOutput creates a new CustomOutput instance with the provided ffuf configuration.
func NewCustomOutput(conf *ffuf.Config) *CustomOutput {
	var outp CustomOutput
	outp.config = conf
	outp.Results = make([]ffuf.Result, 0)
	outp.CurrentResults = make([]ffuf.Result, 0)
	outp.fuzzkeywords = make([]string, 0)
	for _, ip := range conf.InputProviders {
		outp.fuzzkeywords = append(outp.fuzzkeywords, ip.Keyword)
	}
	return &outp
}

func printOption(name []byte, value []byte) {
	fmt.Fprintf(os.Stderr, " :: %-16s : %s\n", name, value)
}

// Banner prints the banner for the ffuf tool, displaying the version, method, URL, wordlist, and other metadata
// during the tool's execution.
func (s *CustomOutput) Banner() {
	version := strings.ReplaceAll(ffuf.Version(), "<3", fmt.Sprintf("%s<3%s", AnsiRed, AnsiClear))
	fmt.Fprintf(os.Stderr, "%s\n", version)
	printOption([]byte("Method"), []byte(s.config.Method))
	printOption([]byte("URL"), []byte(s.config.Url))

	// Print wordlists
	for _, provider := range s.config.InputProviders {
		if provider.Name == "wordlist" {
			printOption([]byte("Wordlist"), []byte(provider.Keyword+": "+provider.Value))
		}
	}

	// Print headers
	if len(s.config.Headers) > 0 {
		for k, v := range s.config.Headers {
			printOption([]byte("Header"), []byte(fmt.Sprintf("%s: %s", k, v)))
		}
	}
	// Print POST data
	if len(s.config.Data) > 0 {
		printOption([]byte("Data"), []byte(s.config.Data))
	}

	// Print extensions
	if len(s.config.Extensions) > 0 {
		exts := ""
		for _, ext := range s.config.Extensions {
			exts = fmt.Sprintf("%s%s ", exts, ext)
		}
		printOption([]byte("Extensions"), []byte(exts))
	}

	// Output file info
	if len(s.config.OutputFile) > 0 {

		// Use filename as specified by user
		OutputFile := s.config.OutputFile

		if s.config.OutputFormat == "all" {
			// Actually... append all extensions
			OutputFile += ".{json,ejson,html,md,csv,ecsv}"
		}

		printOption([]byte("Output file"), []byte(OutputFile))
		printOption([]byte("File format"), []byte(s.config.OutputFormat))
	}

	// Follow redirects?
	follow := fmt.Sprintf("%t", s.config.FollowRedirects)
	printOption([]byte("Follow redirects"), []byte(follow))

	// Autocalibration
	autocalib := fmt.Sprintf("%t", s.config.AutoCalibration)
	printOption([]byte("Calibration"), []byte(autocalib))

	// Proxies
	if len(s.config.ProxyURL) > 0 {
		printOption([]byte("Proxy"), []byte(s.config.ProxyURL))
	}
	if len(s.config.ReplayProxyURL) > 0 {
		printOption([]byte("ReplayProxy"), []byte(s.config.ReplayProxyURL))
	}

	// Timeout
	timeout := fmt.Sprintf("%d", s.config.Timeout)
	printOption([]byte("Timeout"), []byte(timeout))

	// Threads
	threads := fmt.Sprintf("%d", s.config.Threads)
	printOption([]byte("Threads"), []byte(threads))

	// Delay?
	if s.config.Delay.HasDelay {
		delay := ""
		if s.config.Delay.IsRange {
			delay = fmt.Sprintf("%.2f - %.2f seconds", s.config.Delay.Min, s.config.Delay.Max)
		} else {
			delay = fmt.Sprintf("%.2f seconds", s.config.Delay.Min)
		}
		printOption([]byte("Delay"), []byte(delay))
	}

	// Print matchers
	for _, f := range s.config.MatcherManager.GetMatchers() {
		printOption([]byte("Matcher"), []byte(f.ReprVerbose()))
	}
	// Print filters
	for _, f := range s.config.MatcherManager.GetFilters() {
		printOption([]byte("Filter"), []byte(f.ReprVerbose()))
	}
}

// Reset resets the current results for the CustomOutput instance.
func (s *CustomOutput) Reset() {
	s.CurrentResults = make([]ffuf.Result, 0)
}

// Cycle appends the current results to the results list and performs a reset of the current results.
func (s *CustomOutput) Cycle() {
	s.Results = append(s.Results, s.CurrentResults...)
	s.Reset()
}

// GetCurrentResults returns the current results for the CustomOutput instance.
func (s *CustomOutput) GetCurrentResults() []ffuf.Result {
	return s.CurrentResults
}

// SetCurrentResults sets the current results for the CustomOutput instance.
func (s *CustomOutput) SetCurrentResults(results []ffuf.Result) {
	s.CurrentResults = results
}

// Progress prints the current progress of the ffuf tool, including the request count, request rate, duration, and error count.
func (s *CustomOutput) Progress(status ffuf.Progress) {
	if s.config.Quiet {
		// No progress for quiet mode
		return
	}

	dur := time.Since(status.StartedAt)
	runningSecs := int(dur / time.Second)
	var reqRate int64
	if runningSecs > 0 {
		reqRate = status.ReqSec
	} else {
		reqRate = 0
	}

	hours := dur / time.Hour
	dur -= hours * time.Hour
	mins := dur / time.Minute
	dur -= mins * time.Minute
	secs := dur / time.Second

	fmt.Fprintf(os.Stderr, "%s:: Progress: [%d/%d] :: Job [%d/%d] :: %d req/sec :: Duration: [%d:%02d:%02d] :: Errors: %d ::", TerminalClearLine, status.ReqCount, status.ReqTotal, status.QueuePos, status.QueueTotal, reqRate, hours, mins, secs, status.ErrorCount)
}

func (s *CustomOutput) Info(infostring string) {
	fmt.Printf("[INFO] %s\n", infostring)
}

func (s *CustomOutput) Error(errstring string) {
	fmt.Printf("[ERROR] %s\n", errstring)
}

func (s *CustomOutput) Warning(warnstring string) {
	fmt.Printf("[WARNING] %s\n", warnstring)
}

func (s *CustomOutput) Raw(output string) {
	fmt.Printf("%s\n", output)
}

func (s *CustomOutput) Finalize() error {
	// Optional: Do any final processing or cleanup
	return nil
}

func (s *CustomOutput) Result(resp ffuf.Response) {
	inputs := make(map[string][]byte, len(resp.Request.Input))
	for k, v := range resp.Request.Input {
		inputs[k] = v
	}
	sResult := ffuf.Result{
		Input:            inputs,
		Position:         resp.Request.Position,
		StatusCode:       resp.StatusCode,
		ContentLength:    resp.ContentLength,
		ContentWords:     resp.ContentWords,
		ContentLines:     resp.ContentLines,
		ContentType:      resp.ContentType,
		RedirectLocation: resp.GetRedirectLocation(false),
		ScraperData:      resp.ScraperData,
		Url:              resp.Request.Url,
		Duration:         resp.Time,
	}
	s.CurrentResults = append(s.CurrentResults, sResult)
}

func (s *CustomOutput) PrintResult(res ffuf.Result) {
	// You can implement custom result printing logic here or leave it empty
}

func (s *CustomOutput) SaveFile(filename, format string) error {
	// You can implement custom result printing logic here or leave it empty
	return nil
}
