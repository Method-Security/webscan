// Package webserver contains the logic and data structures necessary for the `webcan probe` command
package webserver

import (
	"context"
	"strings"
	"time"

	"github.com/projectdiscovery/httpx/runner"
)

// URLDetails represents the data returned from a probe of a singular URL.
type URLDetails struct {
	URL    string `json:"url" yaml:"url"`
	Status int    `json:"status" yaml:"status"`
	Title  string `json:"title" yaml:"title"`
}

// A ProbeReport represents a holistic report of all the URLs that were probed during a web server probe operation,
type ProbeReport struct {
	Targets []string     `json:"targets" yaml:"targets"`
	URLs    []URLDetails `json:"urls" yaml:"urls"`
	Errors  []string     `json:"errors" yaml:"errors"`
}

func performWebServerProbe(ctx context.Context, targets []string, timeout time.Duration) ([]URLDetails, []string, error) {
	errors := []string{}
	urls := []URLDetails{}

	// Create a new context with timeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	options := runner.Options{
		Methods:         "GET",
		InputTargetHost: targets,
		OnResult: func(r runner.Result) {
			// handle error
			if r.Err != nil {
				errors = append(errors, r.Err.Error())
			}
			urlDetails := URLDetails{
				URL:    r.URL,
				Status: r.StatusCode,
				Title:  r.Title,
			}
			urls = append(urls, urlDetails)
		},
	}

	if err := options.ValidateOptions(); err != nil {
		return urls, errors, err
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		return urls, errors, err
	}
	defer httpxRunner.Close()

	// Run the enumeration with a goroutine and select for timeout
	done := make(chan struct{})

	go func() {
		httpxRunner.RunEnumeration()
		close(done)
	}()

	select {
	case <-ctx.Done():
		// Timeout reached
		return urls, errors, ctx.Err()
	case <-done:
		// Enumeration completed successfully
		return urls, errors, nil
	}
}

// PerformWebServerProbe performs a web server probe against the provided targets, returning a ProbeReport with the
// results of the probe.
func PerformWebServerProbe(ctx context.Context, targets string, timeout time.Duration) (ProbeReport, error) {
	// 1. Parse target list
	targetList := strings.Split(targets, ",")

	// 2. Perform web server probe with timeout
	urls, errors, err := performWebServerProbe(ctx, targetList, timeout)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// 3. Create report
	report := ProbeReport{
		Targets: targetList,
		URLs:    urls,
		Errors:  errors,
	}
	return report, nil
}
