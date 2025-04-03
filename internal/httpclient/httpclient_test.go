package httpclient

import (
	"crypto/tls"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"

	"api-tool/internal/auth" // Import for DigestAuthRoundTripper type check
	"api-tool/internal/config"
	"api-tool/internal/logging"

	"github.com/Azure/go-ntlmssp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// mockRoundTripper is a minimal http.RoundTripper for testing transport types.
type mockRoundTripper struct {
	TLSConfig *tls.Config
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// In real tests, you might return mock responses/errors
	return nil, nil
}

// getBaseTransport gets the underlying http.Transport, digging through wrappers.
func getBaseTransport(client *http.Client) (*http.Transport, bool) {
	if client == nil {
		return nil, false
	}
	rt := client.Transport
	if rt == nil {
		// If Transport is nil, it defaults to http.DefaultTransport
		dt, ok := http.DefaultTransport.(*http.Transport)
		return dt, ok
	}

	// Handle common wrappers we expect
	switch t := rt.(type) {
	case *http.Transport:
		return t, true
	case ntlmssp.Negotiator:
		if baseRT, ok := t.RoundTripper.(*http.Transport); ok {
			return baseRT, true
		}
	case *auth.DigestAuthRoundTripper: // <<< ADDED check for our Digest RT
		if baseRT, ok := t.Next.(*http.Transport); ok {
			return baseRT, true
		}
	case *oauth2.Transport:
		// oauth2.Transport has a Base field which might be nil or another wrapper
		// It might wrap OUR Digest RT which wraps the base... need to check recursively?
		// Let's assume for now OAuth2 directly wraps the *base* via context.
		baseToCheck := t.Base
		if baseToCheck == nil { // If Base is nil, it uses http.DefaultClient internally
			if dt, ok := http.DefaultTransport.(*http.Transport); ok {
				return dt, ok
			}
		} else {
			// Check if Base is directly http.Transport
			if baseRT, ok := baseToCheck.(*http.Transport); ok {
				return baseRT, true
			}
			// Add checks for other wrappers if OAuth2 might wrap them? Unlikely for this setup.
		}
	}
	// Could add more wrappers here if needed
	return nil, false
}


func TestNewClient(t *testing.T) {
	apiCfgBase := config.APIConfig{
		BaseURL:   "http://test.com",
		Endpoints: map[string]config.EndpointConfig{},
	}
	authCfgBase := config.AuthConfig{
		Default: "none",
		Credentials: map[string]string{
			"username":      "user",
			"password":      "pass",
			"api_key":       "key",
			"client_id":     "cid",
			"client_secret": "csec",
			"token_url":     "http://token.com/oauth",
			"scope":         "api_access",
		},
	}

	// Create a persistent jar for testing that scenario
	persistentJar, _ := cookiejar.New(nil)

	tests := []struct {
		name                string
		apiCfg              config.APIConfig
		authCfg             config.AuthConfig
		jarInput            http.CookieJar // Jar to pass in
		fipsModeInput       bool           // <<< ADDED Fips Mode Input
		expectedAuthType    string         // Auth type client should be configured for
		expectTlsSkip       bool
		expectJar           bool // Whether client.Jar should be non-nil
		expectPersistentJar bool // Whether client.Jar should be the specific persistentJar instance
		expectError         bool
		checkTransportType  func(t *testing.T, transport http.RoundTripper) // Function to check transport type
	}{
		{
			name:              "Defaults (No Auth, No Skip, No Jar, FIPS off)",
			apiCfg:            apiCfgBase,
			authCfg:           authCfgBase,
			fipsModeInput:     false, // <<< Pass FIPS mode
			expectedAuthType:  "none",
			expectTlsSkip:     false,
			expectJar:         false,
			checkTransportType: func(t *testing.T, transport http.RoundTripper) {
				_, ok := transport.(*http.Transport)
				assert.True(t, ok, "Expected base http.Transport")
			},
		},
		{
			name:             "TLS Skip Verify Enabled",
			apiCfg:           func() config.APIConfig { c := apiCfgBase; c.TlsSkipVerify = true; return c }(),
			authCfg:          authCfgBase,
			fipsModeInput:    false, // <<< Pass FIPS mode
			expectedAuthType: "none",
			expectTlsSkip:    true,
			expectJar:        false,
		},
		{
			name:             "Cookie Jar Enabled (Temporary)",
			apiCfg:           func() config.APIConfig { c := apiCfgBase; c.CookieJar = true; return c }(),
			authCfg:          authCfgBase,
			fipsModeInput:    false, // <<< Pass FIPS mode
			expectedAuthType: "none",
			expectTlsSkip:    false,
			expectJar:        true,
		},
		{
			name:               "Cookie Jar Enabled (Persistent)",
			apiCfg:             func() config.APIConfig { c := apiCfgBase; c.CookieJar = true; return c }(),
			authCfg:            authCfgBase,
			jarInput:           persistentJar, // Pass the pre-made jar
			fipsModeInput:      false,         // <<< Pass FIPS mode
			expectedAuthType:   "none",
			expectTlsSkip:      false,
			expectJar:          true,
			expectPersistentJar: true,
		},
		{
			name:             "Auth Override API (Basic)",
			apiCfg:           func() config.APIConfig { c := apiCfgBase; c.AuthType = "basic"; return c }(),
			authCfg:          authCfgBase,
			fipsModeInput:    false, // <<< Pass FIPS mode
			expectedAuthType: "basic",
			expectTlsSkip:    false,
			expectJar:        false,
			checkTransportType: func(t *testing.T, transport http.RoundTripper) {
				_, ok := transport.(*http.Transport)
				assert.True(t, ok, "Expected base http.Transport for basic auth")
			},
		},
		{
			name:             "Auth Global Default (Bearer)",
			apiCfg:           apiCfgBase, // No API override
			authCfg:          func() config.AuthConfig { c := authCfgBase; c.Default = "bearer"; return c }(),
			fipsModeInput:    false, // <<< Pass FIPS mode
			expectedAuthType: "bearer",
			expectTlsSkip:    false,
			expectJar:        false,
			checkTransportType: func(t *testing.T, transport http.RoundTripper) {
				_, ok := transport.(*http.Transport)
				assert.True(t, ok, "Expected base http.Transport for bearer auth")
			},
		},
		{
			name:             "NTLM Auth",
			apiCfg:           func() config.APIConfig { c := apiCfgBase; c.AuthType = "ntlm"; return c }(),
			authCfg:          authCfgBase,
			fipsModeInput:    false, // <<< Pass FIPS mode
			expectedAuthType: "ntlm",
			expectTlsSkip:    false,
			expectJar:        false,
			checkTransportType: func(t *testing.T, transport http.RoundTripper) {
				_, ok := transport.(ntlmssp.Negotiator)
				assert.True(t, ok, "Expected ntlmssp.Negotiator transport")
			},
		},
		{
			name:             "NTLM Auth Missing Creds",
			apiCfg:           func() config.APIConfig { c := apiCfgBase; c.AuthType = "ntlm"; return c }(),
			authCfg:          config.AuthConfig{Credentials: map[string]string{}}, // Missing user/pass
			fipsModeInput:    false, // <<< Pass FIPS mode
			expectedAuthType: "ntlm",
			expectError:      true,
		},
		{
			name:             "OAuth2 Auth",
			apiCfg:           func() config.APIConfig { c := apiCfgBase; c.AuthType = "oauth2"; return c }(),
			authCfg:          authCfgBase,
			fipsModeInput:    false, // <<< Pass FIPS mode
			expectedAuthType: "oauth2",
			expectTlsSkip:    false, // Should be propagated to underlying transport
			expectJar:        false,
			checkTransportType: func(t *testing.T, transport http.RoundTripper) {
				_, ok := transport.(*oauth2.Transport)
				assert.True(t, ok, "Expected oauth2.Transport")
			},
		},
		{
			name:               "OAuth2 Auth With Cookie Jar",
			apiCfg:             func() config.APIConfig { c := apiCfgBase; c.AuthType = "oauth2"; c.CookieJar = true; return c }(),
			authCfg:            authCfgBase,
			jarInput:           persistentJar,
			fipsModeInput:      false, // <<< Pass FIPS mode
			expectedAuthType:   "oauth2",
			expectJar:          true, // Jar should be set on the final client
			expectPersistentJar: true,
			checkTransportType: func(t *testing.T, transport http.RoundTripper) {
				_, ok := transport.(*oauth2.Transport)
				assert.True(t, ok, "Expected oauth2.Transport")
			},
		},
		{
			name:             "OAuth2 Auth Missing Creds",
			apiCfg:           func() config.APIConfig { c := apiCfgBase; c.AuthType = "oauth2"; return c }(),
			authCfg:          config.AuthConfig{Credentials: map[string]string{"client_id": "id"}}, // Missing secret/url
			fipsModeInput:    false, // <<< Pass FIPS mode
			expectedAuthType: "oauth2",
			expectError:      true,
		},
		{
			name:             "Digest Auth (FIPS Off)",
			apiCfg:           func() config.APIConfig { c := apiCfgBase; c.AuthType = "digest"; return c }(),
			authCfg:          authCfgBase,
			fipsModeInput:    false, // <<< Pass FIPS mode (off)
			expectedAuthType: "digest",
			checkTransportType: func(t *testing.T, transport http.RoundTripper) {
				// Check it's our Digest RT
				digestRT, ok := transport.(*auth.DigestAuthRoundTripper)
				require.True(t, ok, "Expected *auth.DigestAuthRoundTripper")
				assert.False(t, digestRT.FipsMode, "FipsMode flag should be false in Digest RT")
				// Check it wraps the base transport
				_, okBase := digestRT.Next.(*http.Transport)
				assert.True(t, okBase, "Digest RT should wrap *http.Transport")
			},
		},
        {
            name:             "Digest Auth (FIPS On)",
            apiCfg:           func() config.APIConfig { c := apiCfgBase; c.AuthType = "digest"; return c }(),
            authCfg:          authCfgBase,
            fipsModeInput:    true, // <<< Pass FIPS mode (ON)
            expectedAuthType: "digest",
            checkTransportType: func(t *testing.T, transport http.RoundTripper) {
                digestRT, ok := transport.(*auth.DigestAuthRoundTripper)
                require.True(t, ok, "Expected *auth.DigestAuthRoundTripper")
                assert.True(t, digestRT.FipsMode, "FipsMode flag should be true in Digest RT")
                _, okBase := digestRT.Next.(*http.Transport)
                assert.True(t, okBase, "Digest RT should wrap *http.Transport")
            },
        },
		{
			name:             "Unsupported Auth",
			apiCfg:           func() config.APIConfig { c := apiCfgBase; c.AuthType = "magic"; return c }(),
			authCfg:          authCfgBase,
			fipsModeInput:    false, // <<< Pass FIPS mode
			expectedAuthType: "magic",
			expectError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// <<< MODIFIED: Pass tt.fipsModeInput to NewClient >>>
			client, err := NewClient(&tt.apiCfg, &tt.authCfg, tt.jarInput, tt.fipsModeInput)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				require.NoError(t, err)
				require.NotNil(t, client)

				// Check Jar
				if tt.expectJar {
					assert.NotNil(t, client.Jar)
					if tt.expectPersistentJar {
						assert.Same(t, tt.jarInput, client.Jar, "Expected the persistent jar instance")
					}
				} else {
					assert.Nil(t, client.Jar)
				}

				// Check TLS Skip Verify on the base transport
				baseTransport, ok := getBaseTransport(client)
				require.True(t, ok, "Could not extract base http.Transport")
				require.NotNil(t, baseTransport.TLSClientConfig, "Base transport TLSClientConfig is nil")
				assert.Equal(t, tt.expectTlsSkip, baseTransport.TLSClientConfig.InsecureSkipVerify, "TLSClientConfig.InsecureSkipVerify mismatch")

				// Check Transport Type
				if tt.checkTransportType != nil {
					tt.checkTransportType(t, client.Transport)
				}
			}
		})
	}
}

func TestLogCookieJar(t *testing.T) {
    // This test remains unchanged as LogCookieJar was not affected
    jar, _ := cookiejar.New(nil)
    testURL, _ := url.Parse("http://test.com")
    cookie := &http.Cookie{Name: "session", Value: "123"}
    jar.SetCookies(testURL, []*http.Cookie{cookie})

    // Use a high level first, should not log
    logging.SetLevel(logging.Info)
    LogCookieJar(jar, "http://test.com", logging.GetLevel())
    // TODO: Assert no log output (requires log capture)

    // Use debug level, should log
    logging.SetLevel(logging.Debug)
    LogCookieJar(jar, "http://test.com", logging.GetLevel())
    // TODO: Assert log output contains cookie info (requires log capture)

    // Test with nil jar
    LogCookieJar(nil, "http://test.com", logging.GetLevel())

    // Test with invalid URL
    LogCookieJar(jar, ":invalid-url:", logging.GetLevel())

    // Test with no cookies for URL
    otherURL, _ := url.Parse("http://other.com")
     LogCookieJar(jar, otherURL.String(), logging.GetLevel())


    // Reset log level if needed
    logging.SetLevel(logging.Info)
}