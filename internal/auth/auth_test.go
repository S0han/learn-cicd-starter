package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	testCases := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "no header",
			headers:       make(http.Header),
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header",
			headers: http.Header{
				"Authorization": []string{"Bearer test123"},
			},
			expectedKey:   "",
			expectedError: ErrMalformedAuthHeader,
		},
		{
			name: "valid api key",
			headers: http.Header{
				"Authorization": []string{"ApiKey test123"},
			},
			expectedKey:   "test123",
			expectedError: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)

			if tc.expectedError != nil {
				if err == nil {
					t.Errorf("Expected error %v, got nil", tc.expectedError)
					return
				}
				if err.Error() != tc.expectedError.Error() {
					t.Errorf("Expected error %v, got %v", tc.expectedError, err)
				}
			} else if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if key != tc.expectedKey {
				t.Errorf("Expected key %q, got %q", tc.expectedKey, key)
			}
		})
	}
}
