package auth

import (
	"fmt"
	"net/http"
	"os"

	"api-tool/internal/util"
)

// ApplyAuthHeaders sets request headers for authentication types that use them directly.
// It handles "none", "api_key", "bearer", and "basic".
// NTLM, Digest, and OAuth2 are handled during client creation or request execution.
func ApplyAuthHeaders(req *http.Request, effectiveAuthType string, credentials map[string]string, apiToken string) error {
	switch effectiveAuthType {
	case "none":
		// No headers needed
		return nil
	case "api_key":
		key, ok := credentials["api_key"]
		if !ok {
			return fmt.Errorf("api_key authentication selected, but 'api_key' not found in credentials")
		}
		// Expand env vars in the key itself if needed
		req.Header.Set("Authorization", "Bearer "+util.ExpandEnvUniversal(key))
	case "bearer":
		// Token should be provided via apiToken argument (read from env var in main)
		if apiToken == "" {
			// Check credentials as a fallback? Or strictly enforce ENV? Let's enforce ENV for now.
			return fmt.Errorf("bearer authentication selected, but API_TOKEN environment variable is not set")
		}
		req.Header.Set("Authorization", "Bearer "+apiToken)
	case "basic":
		username, ok1 := credentials["username"]
		password, ok2 := credentials["password"]
		if !ok1 || !ok2 {
			return fmt.Errorf("basic authentication selected, but 'username' or 'password' not found in credentials")
		}
		// Expand env vars in username/password
		req.SetBasicAuth(util.ExpandEnvUniversal(username), util.ExpandEnvUniversal(password))
	case "ntlm":
		// NTLM auth requires setting basic auth initially, the transport handles the negotiation.
		username, ok1 := credentials["username"]
		password, ok2 := credentials["password"]
		if !ok1 || !ok2 {
			return fmt.Errorf("ntlm authentication selected, but 'username' or 'password' not found in credentials")
		}
		// The ntlmssp transport expects initial basic auth credentials
		req.SetBasicAuth(util.ExpandEnvUniversal(username), util.ExpandEnvUniversal(password))
	case "digest":
		// Digest auth is handled during request execution by the executor
		return nil
	case "oauth2":
		// OAuth2 is handled by the client transport
		return nil
	default:
		return fmt.Errorf("unsupported authentication type configured: %s", effectiveAuthType)
	}
	return nil
}

// GetAPIToken retrieves the API token from the environment.
// Kept separate for clarity, although currently only called from main.
func GetAPIToken() string {
	return os.Getenv("API_TOKEN")
}

// NeedsCredentials checks if a given auth type requires credentials map entry.
func NeedsCredentials(authType string) bool {
	switch authType {
	case "api_key", "basic", "ntlm", "digest", "oauth2":
		return true
	default:
		return false
	}
}
