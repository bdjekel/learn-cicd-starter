package auth

import (
	"fmt"
	"net/http"
	"testing"
)

func TestGetAPIKeyValid(t *testing.T) {
	// define test headers
	headers := http.Header{
		"Content-Type":  []string{"application/json"},
		"Authorization": []string{"ApiKey eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
	}

	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Error("Failure retreiving API Key from Header.", err)
		return
	}
	
	fmt.Printf("apiKey Valid\n>>%s<<\n", apiKey)
}

func TestGetAPIKeyEmpty(t *testing.T) {
	// define test headers
	headers := http.Header{
		"Content-Type":  []string{"application/json"},
		"Authorization": []string{""},
	}

	apiKey, err := GetAPIKey(headers)
	switch err {
	case nil:
		t.Errorf("Failure catching malformed API Key from Header.\n>>%s<<\n", apiKey)
	case ErrNoAuthHeaderIncluded:
		fmt.Printf("Successfully caught 'malformed' key error: %s", err)
		return
	default:
		t.Errorf("Failure caught, but incorrect error thrown.\n>>%s<<\n", err)
	}

}

func TestGetAPIKeyMalformed1(t *testing.T) {
	// define test headers
	headers := http.Header{
		"Content-Type":  []string{"application/json"},
		"Authorization": []string{"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
	}

	apiKey, err := GetAPIKey(headers)
	if err != nil {
		fmt.Printf("Successfully caught 'malformed' key error: %s", err)
		return
	}
	t.Errorf("Failure catching malformed API Key from Header.\n>>%s<<\n", apiKey)

}

func TestGetAPIKeyMalformed2(t *testing.T) {
	// define test headers
	headers := http.Header{
		"Content-Type":  []string{"application/json"},
		"Authorization": []string{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
	}

	apiKey, err := GetAPIKey(headers)
	if err != nil {
		fmt.Printf("Successfully caught 'malformed' key error: %s", err)
		return
	}
	t.Errorf("Failure catching malformed API Key from Header.\n>>%s<<\n", apiKey)

}

func TestGetAPIKeyMalformed3(t *testing.T) {
	// define test headers
	headers := http.Header{
		"Content-Type":  []string{"application/json"},
		"Authorization": []string{"ApiKey Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
	}

	apiKey, err := GetAPIKey(headers)
	if err != nil {
		fmt.Printf("Successfully caught 'malformed' key error: %s", err)
		return
	}
	t.Errorf("Failure catching malformed API Key from Header.\n>>%s<<\n", apiKey)

}