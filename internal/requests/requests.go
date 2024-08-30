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

func PerformRequestScan(baseURL, path, method string, params webscan.RequestParams, vulnTypes []string) webscan.RequestReport {
	report := webscan.RequestReport{
		BaseUrl: baseURL,
		Path:    path,
	}

	// Validate and set HTTP method
	httpMethod := strings.ToUpper(method)
	if !isValidHTTPMethod(httpMethod) {
		report.Errors = append(report.Errors, fmt.Sprintf("Invalid HTTP method: %s", method))
		return report
	}
	report.Method = webscan.HttpMethod(httpMethod)

	// Parse parameters
	parsedParams, err := parseAllParams(params)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	// Construct the URL
	fullURL, err := constructURL(baseURL, path, parsedParams.PathParams, parsedParams.QueryParams)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	// Prepare request body and content type
	reqBody, contentType, err := prepareRequestBody(parsedParams)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	// Create and send the request
	resp, err := sendRequest(httpMethod, fullURL.String(), reqBody, contentType, parsedParams.HeaderParams)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
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
	populateReport(&report, resp, body, parsedParams, vulnTypes)

	return report
}

func isValidHTTPMethod(method string) bool {
	validMethods := map[string]bool{
		string(webscan.HttpMethodGet):    true,
		string(webscan.HttpMethodPost):   true,
		string(webscan.HttpMethodPut):    true,
		string(webscan.HttpMethodDelete): true,
		string(webscan.HttpMethodPatch):  true,
	}
	return validMethods[method]
}

func parseJSONParams(jsonStr string) (map[string]string, error) {
	if jsonStr == "" {
		return nil, nil
	}

	var result map[string]interface{}
	err := json.Unmarshal([]byte(jsonStr), &result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	params := make(map[string]string)
	for key, value := range result {
		switch v := value.(type) {
		case string:
			params[key] = v
		default:
			stringValue, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal value for key %s: %v", key, err)
			}
			params[key] = string(stringValue)
		}
	}

	return params, nil
}

func parseAllParams(params webscan.RequestParams) (webscan.ParsedParams, error) {
	var parsed webscan.ParsedParams
	var err error

	parsed.PathParams, err = parseJSONParams(params.PathParams)
	if err != nil {
		return parsed, fmt.Errorf("failed to parse path parameters: %v", err)
	}

	parsed.QueryParams, err = parseJSONParams(params.QueryParams)
	if err != nil {
		return parsed, fmt.Errorf("failed to parse query parameters: %v", err)
	}

	parsed.HeaderParams, err = parseJSONParams(params.HeaderParams)
	if err != nil {
		return parsed, fmt.Errorf("failed to parse header parameters: %v", err)
	}

	parsed.FormParams, err = parseJSONParams(params.FormParams)
	if err != nil {
		return parsed, fmt.Errorf("failed to parse form parameters: %v", err)
	}

	parsed.MultipartParams, err = parseJSONParams(params.MultipartParams)
	if err != nil {
		return parsed, fmt.Errorf("failed to parse multipart parameters: %v", err)
	}

	parsed.BodyParams = params.BodyParams

	return parsed, nil
}

func constructURL(baseURL, path string, pathParams, queryParams map[string]string) (*url.URL, error) {
	fullURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base URL: %v", err)
	}

	endpoint := path
	for key, value := range pathParams {
		endpoint = strings.ReplaceAll(endpoint, fmt.Sprintf("{%s}", key), url.PathEscape(value))
	}
	fullURL.Path = endpoint

	q := fullURL.Query()
	for key, value := range queryParams {
		q.Add(key, value)
	}
	fullURL.RawQuery = q.Encode()

	return fullURL, nil
}

func prepareRequestBody(params webscan.ParsedParams) (io.Reader, string, error) {
	if params.BodyParams != "" {
		if !json.Valid([]byte(params.BodyParams)) {
			return nil, "", fmt.Errorf("invalid JSON in body parameters")
		}
		return strings.NewReader(params.BodyParams), "application/json", nil
	}

	if len(params.FormParams) > 0 {
		formValues := url.Values{}
		for key, value := range params.FormParams {
			formValues.Add(key, value)
		}
		return strings.NewReader(formValues.Encode()), "application/x-www-form-urlencoded", nil
	}

	if len(params.MultipartParams) > 0 {
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		for key, value := range params.MultipartParams {
			if err := writer.WriteField(key, value); err != nil {
				return nil, "", fmt.Errorf("failed to write multipart field: %v", err)
			}
		}
		if err := writer.Close(); err != nil {
			return nil, "", fmt.Errorf("failed to close multipart writer: %v", err)
		}
		return body, writer.FormDataContentType(), nil
	}

	return nil, "", nil
}

func sendRequest(method, url string, body io.Reader, contentType string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	for key, value := range headers {
		req.Header.Add(key, value)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %v", err)
	}

	return resp, nil
}

func populateReport(report *webscan.RequestReport, resp *http.Response, body []byte, params webscan.ParsedParams, vulnTypes []string) {
	report.StatusCode = resp.StatusCode
	report.ResponseBody = string(body)
	report.ResponseHeaders = make(map[string]string)
	for key, values := range resp.Header {
		report.ResponseHeaders[key] = strings.Join(values, ", ")
	}

	if len(params.PathParams) > 0 {
		report.PathParams = params.PathParams
	}
	if len(params.QueryParams) > 0 {
		report.QueryParams = params.QueryParams
	}
	if len(params.HeaderParams) > 0 {
		report.HeaderParams = params.HeaderParams
	}
	if params.BodyParams != "" {
		report.BodyParams = &params.BodyParams
	}
	if len(params.FormParams) > 0 {
		report.FormParams = params.FormParams
	}
	if len(params.MultipartParams) > 0 {
		report.MultipartParams = params.MultipartParams
	}
	if len(vulnTypes) > 0 {
		report.VulnTypes = vulnTypes
	}
}
