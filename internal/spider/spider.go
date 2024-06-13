package spider

import (
	"context"
	"math"
	"strings"

	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
)

type LinkDetails struct {
	Link   string `json:"link" yaml:"link"`
	Status int    `json:"status" yaml:"status"`
}

type WebSpiderReport struct {
	Targets []string      `json:"targets" yaml:"targets"`
	Links   []LinkDetails `json:"links" yaml:"links"`
	Errors  []string      `json:"errors" yaml:"errors"`
}

func performWebSpider(targets []string) ([]LinkDetails, []string, error) {
	errors := []string{}
	links := []LinkDetails{}

	options := &types.Options{
		MaxDepth:     3,             // Maximum depth to crawl
		FieldScope:   "rdn",         // Crawling Scope Field
		BodyReadSize: math.MaxInt,   // Maximum response size to read
		Timeout:      10,            // Timeout is the time to wait for request in seconds
		Concurrency:  10,            // Concurrency is the number of concurrent crawling goroutines
		Parallelism:  10,            // Parallelism is the number of urls processing goroutines
		Delay:        0,             // Delay is the delay between each crawl requests in seconds
		RateLimit:    150,           // Maximum requests to send per second
		Strategy:     "depth-first", // Visit strategy (depth-first, breadth-first)
		OnResult: func(result output.Result) { // Callback function to execute for result
			linkDetails := LinkDetails{
				Link:   result.Request.URL,
				Status: result.Response.StatusCode,
			}
			links = append(links, linkDetails)
		},
	}

	crawlerOptions, err := types.NewCrawlerOptions(options)
	if err != nil {
		return links, errors, err
	}
	//defer crawlerOptions.Close()

	crawler, err := standard.New(crawlerOptions)
	if err != nil {
		return links, errors, err
	}
	//defer crawler.Close()

	for _, target := range targets {
		err := crawler.Crawl(target)
		if err != nil {
			errors = append(errors, err.Error())
		}
	}

	return links, errors, nil

}

func PerformWebSpider(ctx context.Context, targets string) (WebSpiderReport, error) {
	// 1. Parse target list
	targetList := strings.Split(targets, ",")

	// 2. Perform web spider
	links, errors, err := performWebSpider(targetList)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// 3. Create report
	report := WebSpiderReport{
		Targets: targetList,
		Links:   links,
		Errors:  errors,
	}
	return report, nil
}
