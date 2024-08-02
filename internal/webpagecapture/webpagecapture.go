package webpagecapture

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"

	webscan "github.com/Method-Security/webscan/generated/go"
)

// PerformWebpageCapture performs a webpage capture against a target URL
func PerformWebpageCapture(ctx context.Context, target string) *webscan.WebpageCaptureReport {
	report := &webscan.WebpageCaptureReport{
		Target: target,
		Errors: []string{},
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Get(target)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			err = cerr
		}
	}()
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	if resp.StatusCode != http.StatusOK {
		report.Errors = append(report.Errors, "Failed to get the webpage. Status code: "+string(rune(resp.StatusCode)))
		return report
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
	} else {
		bodyString := string(body)
		encodedBodyString := base64.StdEncoding.EncodeToString([]byte(bodyString))
		report.HtmlEncoded = &encodedBodyString
	}

	return report
}
