// Package probe contains the logic and data structures necessary for the `webcan probe` command
package probe

import (
	"context"
	"strings"

	"github.com/projectdiscovery/httpx/runner"
)

// URLDetails represents the data returned from a probe of a singular URL.
type URLDetails struct {
	URL    string `json:"url" yaml:"url"`
	Status int    `json:"status" yaml:"status"`
	Title  string `json:"title" yaml:"title"`
}

// A WebServerReport represents a holistic report of all the URLs that were probed during a web server probe operation,
type WebServerReport struct {
	Targets []string     `json:"targets" yaml:"targets"`
	URLs    []URLDetails `json:"urls" yaml:"urls"`
	Errors  []string     `json:"errors" yaml:"errors"`
}

func performWebServerProbe(targets []string) ([]URLDetails, []string, error) {
	errors := []string{}
	urls := []URLDetails{}

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

	httpxRunner, err := runner.New(&options)
	if err != nil {
		return urls, errors, err
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()

	return urls, errors, nil

}

// PerformWebServerProbe performs a web server probe against the provided targets, returning a WebServerReport with the
// results of the probe.
func PerformWebServerProbe(ctx context.Context, targets string) (WebServerReport, error) {
	// 1. Parse target list
	targetList := strings.Split(targets, ",")

	// 2. Perform web server probe
	urls, errors, err := performWebServerProbe(targetList)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// 3. Create report
	report := WebServerReport{
		Targets: targetList,
		URLs:    urls,
		Errors:  errors,
	}
	return report, nil
}
