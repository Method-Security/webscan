package fuzz

import (
	"bufio"
	"net/http"
	"strings"
)

type HTTPResponseProfile struct {
	StatusCode int
	Words      int
	Lines      int
	Size       int
}

func profileBaseURL(url string) (HTTPResponseProfile, error) {
	// Send HTTP request
	resp, err := http.Get(url)
	if err != nil {
		return HTTPResponseProfile{}, err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			err = cerr
		}
	}()

	// Get HTTP response code
	statusCode := resp.StatusCode

	// Initialize counters
	var size int
	var words, lines int

	// Use a bufio.Scanner to read the response body line by line
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		lines++
		words += len(strings.Fields(line))
		size += len(line) + 1 // +1 for the newline character
	}

	if err := scanner.Err(); err != nil {
		return HTTPResponseProfile{}, err
	}

	return HTTPResponseProfile{StatusCode: statusCode, Words: words, Lines: lines, Size: size}, nil
}
