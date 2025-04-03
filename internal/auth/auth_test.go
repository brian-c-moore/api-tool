package auth

import (
	"net/http"
	"testing"
    "os"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyAuthHeaders(t *testing.T) {
	creds := map[string]string{
		"api_key":  "test-api-key",
		"username": "testuser",
		"password": "testpassword",
		// For OAuth2/Digest/NTLM, presence is checked, but headers are set differently/later
	}
	tokenFromEnv := "test-bearer-token"

	t.Setenv("API_TOKEN", tokenFromEnv)
	t.Setenv("USER", "testuser") // For env expansion tests
	t.Setenv("PASS", "testpassword")
	t.Setenv("APIKEY", "test-api-key")

	tests := []struct {
		name              string
		authType          string
		credentials       map[string]string
		apiToken          string
		expectError       bool
		expectedHeaderKey string
		expectedHeaderVal string // Or check BasicAuth
		expectBasicUser   string
		expectBasicPass   string
	}{
		{"None", "none", creds, tokenFromEnv, false, "", "", "", ""},
		{"API Key", "api_key", creds, "", false, "Authorization", "Bearer test-api-key", "", ""},
		{"API Key Env Expand", "api_key", map[string]string{"api_key": "$APIKEY"}, "", false, "Authorization", "Bearer test-api-key", "", ""},
		{"API Key Missing Cred", "api_key", map[string]string{}, "", true, "", "", "", ""},
		{"Bearer From Arg", "bearer", creds, tokenFromEnv, false, "Authorization", "Bearer "+tokenFromEnv, "", ""},
		{"Bearer Missing Token", "bearer", creds, "", true, "", "", "", ""}, // Env var unset is tested implicitly if apiToken arg is ""
		{"Basic", "basic", creds, "", false, "", "", "testuser", "testpassword"},
		{"Basic Env Expand", "basic", map[string]string{"username": "$USER", "password": "%PASS%"}, "", false, "", "", "testuser", "testpassword"},
		{"Basic Missing User", "basic", map[string]string{"password": "p"}, "", true, "", "", "", ""},
		{"Basic Missing Pass", "basic", map[string]string{"username": "u"}, "", true, "", "", "", ""},
		{"NTLM (Sets Basic)", "ntlm", creds, "", false, "", "", "testuser", "testpassword"}, // NTLM transport expects initial basic auth
		{"NTLM Missing Creds", "ntlm", map[string]string{}, "", true, "", "", "", ""},
		{"Digest (No Headers Applied)", "digest", creds, "", false, "", "", "", ""},   // Handled by executor
		{"OAuth2 (No Headers Applied)", "oauth2", creds, "", false, "", "", "", ""}, // Handled by client transport
		{"Unsupported Type", "kerberos", creds, "", true, "", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com", nil)
			err := ApplyAuthHeaders(req, tt.authType, tt.credentials, tt.apiToken)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.expectedHeaderKey != "" {
					assert.Equal(t, tt.expectedHeaderVal, req.Header.Get(tt.expectedHeaderKey))
				}
				if tt.expectBasicUser != "" || tt.expectBasicPass != "" {
					user, pass, ok := req.BasicAuth()
					assert.True(t, ok, "Expected Basic Auth to be set")
					assert.Equal(t, tt.expectBasicUser, user)
					assert.Equal(t, tt.expectBasicPass, pass)
				} else {
					_, _, ok := req.BasicAuth()
					assert.False(t, ok, "Expected Basic Auth to not be set")
					// Check Authorization header is not set if not expected explicitly
					if tt.expectedHeaderKey != "Authorization" {
						assert.Empty(t, req.Header.Get("Authorization"))
					}
				}
			}
		})
	}
}

func TestGetAPIToken(t *testing.T) {
	t.Run("Token Set", func(t *testing.T) {
		expectedToken := "my-secret-token-123"
		t.Setenv("API_TOKEN", expectedToken)
		actual := GetAPIToken()
		assert.Equal(t, expectedToken, actual)
	})

	t.Run("Token Not Set", func(t *testing.T) {
		// Ensure env var is unset for this subtest if run concurrently
		currentVal, wasSet := os.LookupEnv("API_TOKEN")
		os.Unsetenv("API_TOKEN")
		defer func() {
			if wasSet {
				os.Setenv("API_TOKEN", currentVal)
			}
		}() // Restore original value

		actual := GetAPIToken()
		assert.Empty(t, actual)
	})
}

func TestNeedsCredentials(t *testing.T) {
	tests := []struct {
		authType string
		expected bool
	}{
		{"none", false},
		{"api_key", true},
		{"bearer", false}, // Token comes from env primarily
		{"basic", true},
		{"ntlm", true},
		{"digest", true},
		{"oauth2", true},
		{"unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.authType, func(t *testing.T) {
			assert.Equal(t, tt.expected, NeedsCredentials(tt.authType))
		})
	}
}
