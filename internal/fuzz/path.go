package fuzz

import (
	"context"
	"fmt"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
)

// URLDetails provides the details of a single URL that was fuzzed.
type URLDetails struct {
	URL    string `json:"url" yaml:"url"`
	Status string `json:"status" yaml:"status"`
	Size   int64  `json:"size" yaml:"size"`
}

// A PathReport represents a holistic report of all the URLs that were fuzzed during a path fuzzing operation, including
// non-fatal errors that occurred during the operation.
type PathReport struct {
	Target string       `json:"target" yaml:"target"`
	URLs   []URLDetails `json:"urls" yaml:"urls"`
	Errors []string     `json:"errors" yaml:"errors"`
}

// PerformPathFuzz performs a path fuzzing operation against a target URL, using the provided pathlist and responsecodes
func PerformPathFuzz(ctx context.Context, target string, pathlist string, responsecodes string, maxtime int) (PathReport, error) {

	// 1. Modify context
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 2. Set up the ffuf options
	opts := ffuf.ConfigOptions{
		HTTP: ffuf.HTTPOptions{
			Method:          "GET",
			URL:             target + "/FUZZ",
			FollowRedirects: false,
			Timeout:         10,
		},
		Input: ffuf.InputOptions{
			Wordlists: []string{pathlist + ":FUZZ"},
			InputMode: "clusterbomb",
		},
		Filter: ffuf.FilterOptions{
			Status: "",
			Mode:   "or",
		},
		Matcher: ffuf.MatcherOptions{
			Status: responsecodes,
			Mode:   "or",
		},
		General: ffuf.GeneralOptions{
			AutoCalibration: false,
			Threads:         40,
			MaxTime:         maxtime,
		},
		Output: ffuf.OutputOptions{
			OutputFormat: "stdout",
		},
	}

	// 3. Create ffuf config
	conf, err := ffuf.ConfigFromOptions(&opts, ctx, cancel)
	if err != nil {
		return PathReport{}, err
	}

	// 4. Set up filters and matchers
	err = SetupFilters(&opts, conf)
	if err != nil {
		return PathReport{}, err
	}

	// 5. Prepare Job
	job, err := PrepareJob(conf)
	if err != nil {
		return PathReport{}, err
	}

	// Ensure the output provider is not nil before starting the job
	if job.Output == nil {
		return PathReport{}, nil
	}

	// 6. Start the job
	job.Start()

	// 7. Get the results
	customOutput, ok := job.Output.(*CustomOutput)
	if !ok {
		return PathReport{}, nil
	}

	report := PathReport{
		Target: target,
		URLs:   []URLDetails{},
		Errors: []string{},
	}

	for _, result := range customOutput.CurrentResults {
		report.URLs = append(report.URLs, URLDetails{
			URL:    result.Url,
			Status: fmt.Sprintf("%d", result.StatusCode),
			Size:   result.ContentLength,
		})
	}

	return report, nil
}
