package runner

import (
	"errors"
	"io"
	"log"
	"regexp"
	"strings"

	"github.com/logrusorgru/aurora"
)

type resultStatus string

const (
	ResultHTTPError     resultStatus = "http error"
	ResultResponseError resultStatus = "response error"
	ResultVulnerable    resultStatus = "vulnerable"
	ResultNotVulnerable resultStatus = "not vulnerable"
)

type Result struct {
	ResStatus    resultStatus
	Status       aurora.Value
	Entry        Fingerprint
	ResponseBody string
}

func (c *Config) checkSubdomain(subdomain string) (Result, error) {
	url := subdomain
	if !isValidURL(url) {
		if c.HTTPS {
			url = "https://" + subdomain
		} else {
			url = "http://" + subdomain
		}
	}

	resp, err := c.client.Get(url)
	if err != nil {
		return Result{ResStatus: ResultHTTPError, Status: aurora.Red("HTTP ERROR"), Entry: Fingerprint{}, ResponseBody: ""}, errors.New("http error")
	}

	// Read the response body first
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{ResStatus: ResultResponseError, Status: aurora.Red("RESPONSE ERROR"), Entry: Fingerprint{}, ResponseBody: ""}, errors.New("response error")
	}

	// Close the response body after reading
	if err := resp.Body.Close(); err != nil {
		return Result{ResStatus: ResultHTTPError, Status: aurora.Red("HTTP ERROR"), Entry: Fingerprint{}, ResponseBody: ""}, errors.New("http error")
	}

	body := string(bodyBytes)

	return c.matchResponse(body), nil
}

func (c *Config) matchResponse(body string) Result {
	for _, fp := range c.fingerprints {
		if strings.Contains(body, fp.Fingerprint) {
			if confirmsVulnerability(body, fp) {
				return Result{
					ResStatus:    ResultVulnerable,
					Status:       aurora.Green("VULNERABLE"),
					Entry:        fp,
					ResponseBody: body,
				}
			}
			if hasNonVulnerableIndicators(fp) {
				return Result{
					ResStatus:    ResultNotVulnerable,
					Status:       aurora.Red("NOT VULNERABLE"),
					Entry:        fp,
					ResponseBody: body,
				}
			}
		}
	}
	return Result{
		ResStatus:    ResultNotVulnerable,
		Status:       aurora.Red("NOT VULNERABLE"),
		Entry:        Fingerprint{},
		ResponseBody: body,
	}
}

func hasNonVulnerableIndicators(fp Fingerprint) bool {
	return fp.NXDomain
}

func confirmsVulnerability(body string, fp Fingerprint) bool {
	if fp.NXDomain {
		return false
	}

	if fp.Fingerprint != "" {
		re, err := regexp.Compile(fp.Fingerprint)
		if err != nil {
			log.Printf("Error compiling regex for fingerprint %s: %v", fp.Fingerprint, err)
			return false
		}
		if re.MatchString(body) {
			return true
		}
	}

	return false
}
