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
	Target                  string       `json:"target" yaml:"target"`
	URLs                    []URLDetails `json:"urls" yaml:"urls"`
	UrlsSkipedFromBaseMatch []URLDetails `json:"urls_skiped_from_base_match" yaml:"urls_skiped_from_base_match"`
	Errors                  []string     `json:"errors" yaml:"errors"`
}

// PerformPathFuzz performs a path fuzzing operation against a target URL, using the provided pathlist and responsecodes
func PerformPathFuzz(ctx context.Context, target string, pathlist string, ignorebase bool, responsecodes string, maxtime int) (PathReport, error) {

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

	// 8. Profile the base URL if ignorebase is true
	baseProfile := HTTPResponseProfile{}
	if ignorebase {
		baseProfile, err = profileBaseURL(target)
		if err != nil {
			return PathReport{}, err
		}
	}

	report := PathReport{
		Target:                  target,
		URLs:                    []URLDetails{},
		UrlsSkipedFromBaseMatch: []URLDetails{},
		Errors:                  []string{},
	}

	for _, result := range customOutput.CurrentResults {
		if ignorebase && baseProfile.StatusCode == 200 {
			// ffuz seems to report an extra line for every response, so we need to check for both the base profile lines and the base profile lines + 1
			if result.ContentLength == int64(baseProfile.Size) && (result.ContentLines == int64(baseProfile.Lines)+1 || result.ContentLines == int64(baseProfile.Lines)) {
				report.UrlsSkipedFromBaseMatch = append(report.UrlsSkipedFromBaseMatch, URLDetails{
					URL:    result.Url,
					Status: fmt.Sprintf("%d", result.StatusCode),
					Size:   result.ContentLength,
				})
				continue // Skip this result because it matches the base HTTP profile, likely a redirect
			}
		}
		report.URLs = append(report.URLs, URLDetails{
			URL:    result.Url,
			Status: fmt.Sprintf("%d", result.StatusCode),
			Size:   result.ContentLength,
		})
	}

	return report, nil
}
