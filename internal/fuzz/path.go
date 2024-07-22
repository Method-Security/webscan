package fuzz

import (
	"context"
	"fmt"
	"math"

	webscan "github.com/Method-Security/webscan/generated/go"
	"github.com/ffuf/ffuf/v2/pkg/ffuf"
)

// PerformPathFuzz performs a path fuzzing operation against a target URL, using the provided pathlist and responsecodes
func PerformPathFuzz(ctx context.Context, target string, pathlist string, ignorebase bool, responsecodes string, maxtime int) webscan.FuzzPathReport {
	report := webscan.FuzzPathReport{
		Target:                   target,
		Urls:                     []*webscan.UrlDetails{},
		UrlsSkippedFromBaseMatch: []*webscan.UrlDetails{},
		Errors:                   []string{},
	}

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
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	// 4. Set up filters and matchers
	err = SetupFilters(&opts, conf)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	// 5. Prepare Job
	job, err := PrepareJob(conf)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	// Ensure the output provider is not nil before starting the job
	if job.Output == nil {
		report.Errors = append(report.Errors, "job output provider is nil")
		return report
	}

	// 6. Start the job
	job.Start()

	// 7. Get the results
	customOutput, ok := job.Output.(*CustomOutput)
	if !ok {
		report.Errors = append(report.Errors, "custom output provider errored")
		return report
	}

	// 8. Profile the base URL if ignorebase is true
	baseProfile := HTTPResponseProfile{}
	if ignorebase {
		baseProfile, err = profileBaseURL(target)
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
			return report
		}
	}

	for _, result := range customOutput.CurrentResults {
		if ignorebase && baseProfile.StatusCode == 200 {
			// ffuz seems to report an extra byte and line for every response, so we need to check accordingly
			if (result.ContentLength == int64(baseProfile.Size) || math.Abs(float64(result.ContentLength-int64(baseProfile.Size))) <= 1) && (result.ContentLines == int64(baseProfile.Lines) || math.Abs(float64(result.ContentLines-int64(baseProfile.Lines))) <= 1) {
				report.UrlsSkippedFromBaseMatch = append(report.UrlsSkippedFromBaseMatch, &webscan.UrlDetails{
					Url:    result.Url,
					Status: fmt.Sprintf("%d", result.StatusCode),
					Size:   int(result.ContentLength),
				})
				continue // Skip this result because it matches the base HTTP profile, likely a redirect
			}
		}
		report.Urls = append(report.Urls, &webscan.UrlDetails{
			Url:    result.Url,
			Status: fmt.Sprintf("%d", result.StatusCode),
			Size:   int(result.ContentLength),
		})
	}

	return report
}
