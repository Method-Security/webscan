package runner

import (
	"log"
	"strings"
	"sync"

	webscan "github.com/Method-Security/webscan/generated/go"
	"github.com/logrusorgru/aurora"
)

func Process(config *Config) (*webscan.SubdomainTakeoverReport, error) {
	resources := webscan.SubdomainTakeoverReport{}
	errs := []string{}

	config.initHTTPClient()
	err := config.loadFingerprints()
	if err != nil {
		return &resources, err
	}

	subdomains := getSubdomains(config)

	const ExtraChannelCapacity = 5
	subdomainCh := make(chan string, config.Concurrency+ExtraChannelCapacity)
	resCh := make(chan *subdomainResult, config.Concurrency)

	var wg sync.WaitGroup
	wg.Add(config.Concurrency)

	var sdtResults []*webscan.SubdomainTakeover
	for i := 0; i < config.Concurrency; i++ {
		go processor(subdomainCh, resCh, config, &wg, &sdtResults, &errs)
	}

	distributeSubdomains(subdomains, subdomainCh)
	wg.Wait()
	close(resCh)

	resources.SubdomainTakeovers = sdtResults
	resources.Errors = errs
	return &resources, nil
}

func processor(subdomainCh <-chan string, resCh chan<- *subdomainResult, c *Config, wg *sync.WaitGroup, sdtResults *[]*webscan.SubdomainTakeover, errs *[]string) {
	defer wg.Done()
	for subdomain := range subdomainCh {
		result, err := c.checkSubdomain(subdomain)
		res := &subdomainResult{
			Subdomain:     subdomain,
			Status:        string(result.ResStatus),
			Engine:        result.Entry.Service,
			Documentation: result.Entry.Documentation,
		}

		var service *string
		if result.Entry.Service != "" {
			service = &result.Entry.Service
		}

		if err == nil {
			sdtResult := webscan.SubdomainTakeover{
				Target:     subdomain,
				Vulnerable: result.Status == aurora.Green("VULNERABLE"),
				Service:    service,
			}
			*sdtResults = append(*sdtResults, &sdtResult)
		} else {
			*errs = append(*errs, err.Error())
		}
		resCh <- res
	}
}

func distributeSubdomains(subdomains []string, subdomainCh chan<- string) {
	for _, subdomain := range subdomains {
		subdomainCh <- subdomain
	}
	close(subdomainCh)
}

func getSubdomains(c *Config) []string {
	if c.Target == "" {
		subdomains, err := readSubdomains(c.Targets)
		if err != nil {
			log.Fatalf("Error reading subdomains: %s", err)
		}
		return subdomains
	}
	return strings.Split(c.Target, ",")
}
