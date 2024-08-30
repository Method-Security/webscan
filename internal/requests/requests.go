package requests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go"
)

func PerformRequestScan(baseURL, path, method, pathParamsJSON, queryParamsJSON, headerParamsJSON, bodyParamsJSON, formParamsJSON, multipartParamsJSON string, vulnTypes []string) webscan.RequestReport {
	report := webscan.RequestReport{
		BaseUrl: baseURL,
		Path:    path,
	}

	// Validate and set HTTP method
	httpMethod := strings.ToUpper(method)
	switch httpMethod {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		report.Method = webscan.HttpMethod(httpMethod)
	default:
		report.Errors = append(report.Errors, fmt.Sprintf("Invalid HTTP method: %s", method))
		return report
	}

	// Parse parameters
	pathParams, err := parseJSONParams(pathParamsJSON)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("Failed to parse path parameters: %v", err))
	}
	queryParams, err := parseJSONParams(queryParamsJSON)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("Failed to parse query parameters: %v", err))
	}
	headerParams, err := parseJSONParams(headerParamsJSON)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("Failed to parse header parameters: %v", err))
	}
	formParams, err := parseJSONParams(formParamsJSON)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("Failed to parse form parameters: %v", err))
	}
	multipartParams, err := parseJSONParams(multipartParamsJSON)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("Failed to parse multipart parameters: %v", err))
	}

	// Construct the URL
	fullURL, err := url.Parse(baseURL)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("Failed to parse base URL: %v", err))
		return report
	}

	// Replace path parameters
	endpoint := path
	for key, value := range pathParams {
		endpoint = strings.ReplaceAll(endpoint, fmt.Sprintf("{%s}", key), url.PathEscape(value))
	}
	fullURL.Path = endpoint

	// Add query parameters
	q := fullURL.Query()
	for key, value := range queryParams {
		q.Add(key, value)
	}
	fullURL.RawQuery = q.Encode()

	// Prepare request body
	var reqBody io.Reader
	var contentType string

	if bodyParamsJSON != "" {
		if !json.Valid([]byte(bodyParamsJSON)) {
			report.Errors = append(report.Errors, "Invalid JSON in body parameters")
			return report
		}
		reqBody = strings.NewReader(bodyParamsJSON)
		contentType = "application/json"
	} else if len(formParams) > 0 {
		formValues := url.Values{}
		for key, value := range formParams {
			formValues.Add(key, value)
		}
		reqBody = strings.NewReader(formValues.Encode())
		contentType = "application/x-www-form-urlencoded"
	} else if len(multipartParams) > 0 {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		for key, value := range multipartParams {
			err := writer.WriteField(key, value)
			if err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("Failed to write multipart field: %v", err))
				return report
			}
		}
		err := writer.Close()
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("Failed to close multipart writer: %v", err))
			return report
		}
		reqBody = body
		contentType = writer.FormDataContentType()
	}

	// Create the request
	req, err := http.NewRequest(httpMethod, fullURL.String(), reqBody)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("Failed to create request: %v", err))
		return report
	}

	// Add headers
	for key, value := range headerParams {
		req.Header.Add(key, value)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	// Perform the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("Failed to perform request: %v", err))
		return report
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("Failed to read response body: %v", err))
		return report
	}

	// Populate report
	report.StatusCode = resp.StatusCode
	report.ResponseBody = string(body)
	report.ResponseHeaders = make(map[string]string)
	for key, values := range resp.Header {
		report.ResponseHeaders[key] = strings.Join(values, ", ")
	}

	// Add parameters to report
	if len(pathParams) > 0 {
		report.PathParams = pathParams
	}
	if len(queryParams) > 0 {
		report.QueryParams = queryParams
	}
	if len(headerParams) > 0 {
		report.HeaderParams = headerParams
	}
	if bodyParamsJSON != "" {
		report.BodyParams = &bodyParamsJSON
	}
	if len(formParams) > 0 {
		report.FormParams = formParams
	}
	if len(multipartParams) > 0 {
		report.MultipartParams = multipartParams
	}
	if len(vulnTypes) > 0 {
		report.VulnTypes = vulnTypes
	}

	return report
}

func parseJSONParams(jsonStr string) (map[string]string, error) {
	params := make(map[string]string)
	if jsonStr != "" {
		err := json.Unmarshal([]byte(jsonStr), &params)
		if err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %v", err)
		}
	}
	return params, nil
}
