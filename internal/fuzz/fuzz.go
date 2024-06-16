package fuzz

import (
	"fmt"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
	"github.com/ffuf/ffuf/v2/pkg/filter"
	"github.com/ffuf/ffuf/v2/pkg/input"
	"github.com/ffuf/ffuf/v2/pkg/runner"
)

// PrepareJob creates a new ffuf job with the provided configuration, leveraging the CustomOutput ffuf type to provide
// control over the output.
func PrepareJob(conf *ffuf.Config) (*ffuf.Job, error) {
	job := ffuf.NewJob(conf)

	var errs ffuf.Multierror
	job.Input, errs = input.NewInputProvider(conf)

	job.Runner = runner.NewRunnerByName("http", conf, false)
	if job.Runner == nil {
		return nil, fmt.Errorf("error creating runner")
	}

	job.Output = NewCustomOutput(conf)
	if job.Output == nil {
		return nil, fmt.Errorf("error creating output provider")
	}

	return job, errs.ErrorOrNil()
}

// SetupFilters sets up the filters for the ffuf job based on the provided configuration options.
func SetupFilters(parseOpts *ffuf.ConfigOptions, conf *ffuf.Config) error {
	errs := ffuf.NewMultierror()
	conf.MatcherManager = filter.NewMatcherManager()
	// If any other matcher is set, ignore -mc default value
	matcherSet := false
	statusSet := false
	warningIgnoreBody := false

	// Check if any matchers or filters are explicitly set
	if parseOpts.Matcher.Status != "" {
		statusSet = true
	}
	if parseOpts.Matcher.Size != "" || parseOpts.Matcher.Regexp != "" || parseOpts.Matcher.Words != "" || parseOpts.Matcher.Lines != "" || parseOpts.Matcher.Time != "" {
		matcherSet = true
		warningIgnoreBody = true
	}
	if parseOpts.Filter.Status != "" || parseOpts.Filter.Size != "" || parseOpts.Filter.Regexp != "" || parseOpts.Filter.Words != "" || parseOpts.Filter.Lines != "" || parseOpts.Filter.Time != "" {
		matcherSet = true
		warningIgnoreBody = true
	}

	// Only set default matchers if no other matchers or filters are set
	if statusSet || !matcherSet {
		if err := conf.MatcherManager.AddMatcher("status", parseOpts.Matcher.Status); err != nil {
			errs.Add(err)
		}
	}

	if parseOpts.Filter.Status != "" {
		if err := conf.MatcherManager.AddFilter("status", parseOpts.Filter.Status, false); err != nil {
			errs.Add(err)
		}
	}
	if parseOpts.Filter.Size != "" {
		warningIgnoreBody = true
		if err := conf.MatcherManager.AddFilter("size", parseOpts.Filter.Size, false); err != nil {
			errs.Add(err)
		}
	}
	if parseOpts.Filter.Regexp != "" {
		if err := conf.MatcherManager.AddFilter("regexp", parseOpts.Filter.Regexp, false); err != nil {
			errs.Add(err)
		}
	}
	if parseOpts.Filter.Words != "" {
		warningIgnoreBody = true
		if err := conf.MatcherManager.AddFilter("word", parseOpts.Filter.Words, false); err != nil {
			errs.Add(err)
		}
	}
	if parseOpts.Filter.Lines != "" {
		warningIgnoreBody = true
		if err := conf.MatcherManager.AddFilter("line", parseOpts.Filter.Lines, false); err != nil {
			errs.Add(err)
		}
	}
	if parseOpts.Filter.Time != "" {
		if err := conf.MatcherManager.AddFilter("time", parseOpts.Filter.Time, false); err != nil {
			errs.Add(err)
		}
	}
	if parseOpts.Matcher.Size != "" {
		if err := conf.MatcherManager.AddMatcher("size", parseOpts.Matcher.Size); err != nil {
			errs.Add(err)
		}
	}
	if parseOpts.Matcher.Regexp != "" {
		if err := conf.MatcherManager.AddMatcher("regexp", parseOpts.Matcher.Regexp); err != nil {
			errs.Add(err)
		}
	}
	if parseOpts.Matcher.Words != "" {
		if err := conf.MatcherManager.AddMatcher("word", parseOpts.Matcher.Words); err != nil {
			errs.Add(err)
		}
	}
	if parseOpts.Matcher.Lines != "" {
		if err := conf.MatcherManager.AddMatcher("line", parseOpts.Matcher.Lines); err != nil {
			errs.Add(err)
		}
	}
	if parseOpts.Matcher.Time != "" {
		if err := conf.MatcherManager.AddMatcher("time", parseOpts.Matcher.Time); err != nil {
			errs.Add(err)
		}
	}
	if conf.IgnoreBody && warningIgnoreBody {
		fmt.Printf("*** Warning: possible undesired combination of -ignore-body and the response options: fl,fs,fw,ml,ms and mw.\n")
	}
	return errs.ErrorOrNil()
}
