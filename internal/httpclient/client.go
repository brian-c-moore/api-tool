package httpclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"api-tool/internal/auth"
	"api-tool/internal/config"
	"api-tool/internal/logging"

	"github.com/Azure/go-ntlmssp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// DefaultTimeout is the default HTTP client timeout.
const DefaultTimeout = 30 * time.Second

// NewClient creates an *http.Client configured based on API and Auth settings.
// Handles TLS verification skipping, NTLM, OAuth2 client credentials flow, Digest, and cookie jars.
// `jar` argument allows providing a persistent cookie jar (e.g., for chains). If nil,
// a temporary one is created if apiCfg.CookieJar is true, otherwise no jar is used.
// <<< MODIFIED Signature: Added fipsMode parameter >>>
func NewClient(apiCfg *config.APIConfig, authCfg *config.AuthConfig, jar http.CookieJar, fipsMode bool) (*http.Client, error) {
	// Determine effective auth type
	effectiveAuthType := strings.ToLower(apiCfg.AuthType)
	if effectiveAuthType == "" && authCfg != nil {
		effectiveAuthType = strings.ToLower(authCfg.Default)
	}

	// Base transport with TLS settings
	baseTransport := &http.Transport{ // Renamed to baseTransport
		// TODO: Configure proxy from environment or config?
		// Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: apiCfg.TlsSkipVerify,
		},
		// Add reasonable defaults for timeouts, keep-alives etc.
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true, // Keep true by default, let TLSNextProto handle forcing HTTP/1.1
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Force HTTP/1.1 if configured
	if apiCfg.ForceHTTP1 {
		logging.Logf(logging.Info, "Forcing HTTP/1.1 for API: %s", apiCfg.BaseURL)
		// Disable HTTP/2 negotiation via ALPN
		baseTransport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		baseTransport.ForceAttemptHTTP2 = false // Also explicitly disable the http2 transport attempt
	}

	if apiCfg.TlsSkipVerify {
		logging.Logf(logging.Info, "TLS certificate verification is DISABLED for API base URL: %s", apiCfg.BaseURL)
	}
	if fipsMode {
		logging.Logf(logging.Info, "FIPS Mode is ENABLED. Non-FIPS algorithms (e.g., MD5 Digest) will be disallowed.")
	}


	// Determine the final transport based on auth type
	var finalTransport http.RoundTripper = baseTransport // Start with the base

	switch effectiveAuthType {
	case "ntlm":
		logging.Logf(logging.Debug, "Configuring NTLM transport for API: %s", apiCfg.BaseURL)
		if authCfg == nil || authCfg.Credentials["username"] == "" || authCfg.Credentials["password"] == "" {
			return nil, fmt.Errorf("ntlm authentication requires username and password in auth credentials")
		}
        // Ensure NTLM forces HTTP/1.1 if ForceHTTP1 is set
        // The ForceHTTP1 logic above already modifies baseTransport, which ntlmssp wraps.
		finalTransport = ntlmssp.Negotiator{RoundTripper: baseTransport} // Wrap baseTransport

	case "digest":
		logging.Logf(logging.Debug, "Configuring Digest transport wrapper for API: %s", apiCfg.BaseURL)
		if authCfg == nil || authCfg.Credentials["username"] == "" || authCfg.Credentials["password"] == "" {
			return nil, fmt.Errorf("digest authentication requires username and password in auth credentials")
		}
		// Use the new DigestAuthRoundTripper from the auth package
		// Pass fipsMode
		finalTransport = &auth.DigestAuthRoundTripper{
			Username: authCfg.Credentials["username"],
			Password: authCfg.Credentials["password"],
			FipsMode: fipsMode, // Pass the flag
			Next:     baseTransport, // Wrap baseTransport (which might be HTTP/1.1 forced)
		}

	case "oauth2":
		// OAuth2 client credentials flow replaces the client entirely,
		// but injects the baseTransport for its underlying requests.
		logging.Logf(logging.Debug, "Configuring OAuth2 client credentials flow for API: %s", apiCfg.BaseURL)
		if authCfg == nil {
			return nil, fmt.Errorf("oauth2 configuration requires 'auth' section in config")
		}
		// Check FIPS mode for OAuth2 
		if fipsMode {
			// Check if Go's crypto libraries are FIPS compliant in this build/environment.
			// This is complex and usually handled by build tags or OS-level settings.
			// For now, just log a note. A real implementation might check crypto/tls/fipsonly.
			logging.Logf(logging.Info, "FIPS Mode enabled for OAuth2. Ensure Go crypto backend is FIPS compliant.")
		}
		creds := authCfg.Credentials
		clientID, ok1 := creds["client_id"]
		clientSecret, ok2 := creds["client_secret"]
		tokenURL, ok3 := creds["token_url"]
		if !ok1 || !ok2 || !ok3 {
			return nil, fmt.Errorf("oauth2 requires client_id, client_secret, and token_url in credentials")
		}
		scope := creds["scope"] // Scope is optional

		oauthConfig := clientcredentials.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			TokenURL:     tokenURL,
			Scopes:       strings.Split(scope, " "), // Split scopes by space
			// TODO: Add AuthStyle configuration?
		}

		// Configure the context with an HTTP client that uses our (potentially HTTP/1.1 forced) baseTransport
		ctxClient := &http.Client{
			Transport: baseTransport, // Use baseTransport here
			Timeout:   DefaultTimeout, // Inherit timeout
			// Jar is handled below for the final oauthClient
		}
		ctx := context.WithValue(context.Background(), oauth2.HTTPClient, ctxClient)

		// Get the OAuth2-aware client. This client uses the ctxClient internally.
		oauthClient := oauthConfig.Client(ctx)

		// Configure cookie jar for the *final* client
		if apiCfg.CookieJar {
			if jar == nil {
				var err error
				jar, err = cookiejar.New(nil)
				if err != nil {
					return nil, fmt.Errorf("failed to create temporary cookie jar for OAuth2 client: %w", err)
				}
				logging.Logf(logging.Debug, "Created temporary cookie jar for OAuth2 API: %s", apiCfg.BaseURL)
			} else {
				logging.Logf(logging.Debug, "Using provided persistent cookie jar for OAuth2 API: %s", apiCfg.BaseURL)
			}
			oauthClient.Jar = jar // Set the jar on the final OAuth2 client
		} else {
			oauthClient.Jar = nil // Ensure no jar if not requested
		}

		// Return the fully configured OAuth2 client directly
		return oauthClient, nil

	case "basic", "bearer", "api_key", "none", "":
		// No special transport needed. Headers applied later.
		break // finalTransport remains baseTransport (which might be HTTP/1.1 forced)

	default:
		return nil, fmt.Errorf("unsupported authentication type '%s' for client creation", effectiveAuthType)
	}

	// --- Configure the final client for non-OAuth2 cases ---
	client := &http.Client{
		Timeout:   DefaultTimeout,
		Transport: finalTransport, // Use the potentially wrapped (and potentially HTTP/1.1 forced) transport
	}

	// Configure cookie jar (if not already handled by OAuth2 path)
	if apiCfg.CookieJar {
		if jar == nil {
			var err error
			jar, err = cookiejar.New(nil)
			if err != nil {
				return nil, fmt.Errorf("failed to create temporary cookie jar: %w", err)
			}
			logging.Logf(logging.Debug, "Created temporary cookie jar for API: %s", apiCfg.BaseURL)
		} else {
			logging.Logf(logging.Debug, "Using provided persistent cookie jar for API: %s", apiCfg.BaseURL)
		}
		client.Jar = jar
	}

	return client, nil
}

// LogCookieJar logs the cookies present in the jar for a given URL.
func LogCookieJar(jar http.CookieJar, urlStr string, logLevel int) {
	if jar == nil || logLevel < logging.Debug {
		return
	}
	u, err := url.Parse(urlStr)
	if err != nil {
		logging.Logf(logging.Debug, "Error parsing URL '%s' for logging cookie jar: %v", urlStr, err)
		return
	}
	cookies := jar.Cookies(u)
	if len(cookies) > 0 {
		logging.Logf(logging.Debug, "Cookies in jar for URL '%s': %v", urlStr, cookies)
	} else {
		logging.Logf(logging.Debug, "No cookies in jar for URL '%s'", urlStr)
	}
}
