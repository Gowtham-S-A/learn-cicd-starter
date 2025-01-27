package auth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		expected   string
		expectErr  bool
		errMessage string
	}{
		{
			name:      "Valid ApiKey header",
			headers:   http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expected:  "my-secret-key",
			expectErr: false,
		},
		{
			name:       "Missing Authorization header",
			headers:    http.Header{},
			expected:   "",
			expectErr:  true,
			errMessage: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:       "Malformed Authorization header (no ApiKey)",
			headers:    http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			expected:   "",
			expectErr:  true,
			errMessage: "malformed authorization header",
		},
		{
			name:       "Malformed Authorization header (missing key)",
			headers:    http.Header{"Authorization": []string{"ApiKey"}},
			expected:   "",
			expectErr:  true,
			errMessage: "malformed authorization header",
		},
		{
			name:       "Empty Authorization value",
			headers:    http.Header{"Authorization": []string{""}},
			expected:   "",
			expectErr:  true,
			errMessage: "no authorization header included",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := GetAPIKey(tc.headers)

			// Assert results
			if tc.expectErr {
				assert.Error(t, err)
				assert.Equal(t, tc.errMessage, err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}
