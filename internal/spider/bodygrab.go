package spider

import (
	"crypto/tls"
	"io"
	"net/http"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
)

func BodyGrab(targets []string, setHTTP bool, timeout int) (*webscan.BodyGrabReport, error) {
	resources := webscan.BodyGrabReport{}
	errs := []string{}

	httpClient := createHTTPClient(setHTTP, timeout)

	var bodyGrabResults []*webscan.BodyGrab
	for _, target := range targets {

		responseBody, statusCode, err := bodyGrab(target, httpClient)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		bodyGrabResult := webscan.BodyGrab{
			Target:       target,
			ResponseBody: responseBody,
			StatusCode:   statusCode,
		}
		bodyGrabResults = append(bodyGrabResults, &bodyGrabResult)
	}

	resources.BodyGrabs = bodyGrabResults
	resources.Errors = errs
	return &resources, nil
}

func createHTTPClient(setHTTP bool, timeout int) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !setHTTP},
	}
	return &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: tr,
	}
}

func bodyGrab(url string, client *http.Client) (string, int, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", 0, err
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}

	err = resp.Body.Close()
	if err != nil {
		return "", 0, err
	}

	statusCode := resp.StatusCode
	body := string(bodyBytes)

	return body, statusCode, nil
}
