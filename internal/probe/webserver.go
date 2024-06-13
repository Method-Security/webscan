package probe

import (
	"context"
	"strings"

	"github.com/projectdiscovery/httpx/runner"
)

type URLDetails struct {
	URL    string `json:"url" yaml:"url"`
	Status int    `json:"status" yaml:"status"`
	Title  string `json:"title" yaml:"title"`
}

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
