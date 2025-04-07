package auth

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockNextRoundTripper simulates the next transport in the chain.
type mockNextRoundTripper struct {
	RoundTripFunc func(req *http.Request) (*http.Response, error)
	Requests      []*http.Request // Capture requests received
}

func (m *mockNextRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone request body if present to allow multiple reads during testing
    var bodyBytes []byte
    var err error
    if req.Body != nil {
        bodyBytes, err = io.ReadAll(req.Body)
        if err != nil {
            panic(fmt.Sprintf("mockNextRoundTripper failed to read request body: %v", err)) // Panic in mock is okay
        }
        req.Body.Close() // Close original
        // Restore body for the actual RoundTripFunc and for capturing
        req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
    }

	reqClone := req.Clone(req.Context()) // Clone to capture state
    if len(bodyBytes) > 0 {
        reqClone.Body = io.NopCloser(bytes.NewReader(bodyBytes)) // Add body to clone if needed
    }

	m.Requests = append(m.Requests, reqClone)

	if m.RoundTripFunc == nil {
		return nil, fmt.Errorf("mockNextRoundTripper.RoundTripFunc not set")
	}
	// Restore body again before calling the actual func, as cloning might advance reader
    if len(bodyBytes) > 0 {
         req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
    }
	return m.RoundTripFunc(req)
}


// Helper to create a mock response
func newMockDigestResponse(statusCode int, headers http.Header, body string) *http.Response {
	if headers == nil {
		headers = make(http.Header)
	}
	return &http.Response{
		StatusCode: statusCode,
		Header:     headers,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    &http.Request{Method: "GET", URL: &url.URL{Scheme: "http", Host: "mock.test", Path: "/test"}}, // Dummy request using mock host
	}
}

// --- Test Cases for DigestAuthRoundTripper ---

func TestDigestAuthRoundTripper_Success_MD5(t *testing.T) {
	mockNext := &mockNextRoundTripper{}
	digestRT := &DigestAuthRoundTripper{
		Username: "testuser",
		Password: "testpass",
		FipsMode: false, // FIPS OFF
		Next:     mockNext,
	}
	initialReq, _ := http.NewRequest("GET", "http://mock.test/protected", nil) // Use mock host
	challengeHeader := `Digest realm="TestRealm", qop="auth", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41", algorithm=MD5`
	mockFunc := func(calls *int) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			*calls++
			if *calls == 1 {
				return newMockDigestResponse(http.StatusUnauthorized, http.Header{"Www-Authenticate": {challengeHeader}}, "Unauthorized"), nil
			} else if *calls == 2 {
				auth := req.Header.Get("Authorization")
				require.NotEmpty(t, auth)
				assert.Contains(t, auth, "algorithm=MD5") // Check MD5 was used
				assert.Contains(t, auth, "qop=auth")
				return newMockDigestResponse(http.StatusOK, nil, "Success Body"), nil
			}
			return nil, fmt.Errorf("too many calls")
		}
	}
	callCount := 0
	mockNext.RoundTripFunc = mockFunc(&callCount)

	finalResp, err := digestRT.RoundTrip(initialReq)

	require.NoError(t, err)
	require.NotNil(t, finalResp)
	assert.Equal(t, http.StatusOK, finalResp.StatusCode)
	bodyBytes, _ := io.ReadAll(finalResp.Body)
	finalResp.Body.Close()
	assert.Equal(t, "Success Body", string(bodyBytes))
	assert.Equal(t, 2, callCount)
}

func TestDigestAuthRoundTripper_Success_SHA256_Preferred(t *testing.T) {
	mockNext := &mockNextRoundTripper{}
	digestRT := &DigestAuthRoundTripper{
		Username: "testuser",
		Password: "testpass",
		FipsMode: false, // FIPS OFF, but SHA-256 should still be preferred
		Next:     mockNext,
	}
	initialReq, _ := http.NewRequest("GET", "http://mock.test/protected", nil) // Use mock host
	// Server offers SHA-256 first (or only)
	challengeHeader := `Digest realm="TestRealm", qop="auth, auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41", algorithm=SHA-256`
	mockFunc := func(calls *int) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			*calls++
			if *calls == 1 {
				return newMockDigestResponse(http.StatusUnauthorized, http.Header{"Www-Authenticate": {challengeHeader}}, "Unauthorized"), nil
			} else if *calls == 2 {
				auth := req.Header.Get("Authorization")
				require.NotEmpty(t, auth)
				assert.Contains(t, auth, "algorithm=SHA-256") // Check SHA-256 was used
				assert.Contains(t, auth, "qop=auth-int")      // Check auth-int was preferred
				return newMockDigestResponse(http.StatusOK, nil, "Success Body"), nil
			}
			return nil, fmt.Errorf("too many calls")
		}
	}
	callCount := 0
	mockNext.RoundTripFunc = mockFunc(&callCount)

	finalResp, err := digestRT.RoundTrip(initialReq)

	require.NoError(t, err)
	require.NotNil(t, finalResp)
	assert.Equal(t, http.StatusOK, finalResp.StatusCode)
	assert.Equal(t, 2, callCount)
}

func TestDigestAuthRoundTripper_FIPS_Mode_Fail_MD5_Only(t *testing.T) {
	mockNext := &mockNextRoundTripper{}
	digestRT := &DigestAuthRoundTripper{
		Username: "testuser",
		Password: "testpass",
		FipsMode: true, // <<< FIPS ON
		Next:     mockNext,
	}
	initialReq, _ := http.NewRequest("GET", "http://mock.test/protected", nil) // Use mock host
	// Server *only* offers MD5
	challengeHeader := `Digest realm="TestRealm", qop="auth", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41", algorithm=MD5`
	callCount := 0
	mockNext.RoundTripFunc = func(req *http.Request) (*http.Response, error) {
		callCount++
		if callCount == 1 {
			return newMockDigestResponse(http.StatusUnauthorized, http.Header{"Www-Authenticate": {challengeHeader}}, "Unauthorized"), nil
		}
		// Should not be called a second time
		t.Fatalf("mockNextRoundTripper called unexpectedly (%d times)", callCount)
		return nil, fmt.Errorf("too many calls")
	}

	finalResp, err := digestRT.RoundTrip(initialReq)

	require.Error(t, err)
	assert.Nil(t, finalResp)
	// Check if the error is the specific FIPS compliance error
	assert.ErrorIs(t, err, ErrDigestFIPSCompliance, "Expected FIPS compliance error")
	assert.Equal(t, 1, callCount, "Expected only 1 call (the initial probe)")
}

func TestDigestAuthRoundTripper_FIPS_Mode_Success_SHA256_Offered(t *testing.T) {
	mockNext := &mockNextRoundTripper{}
	digestRT := &DigestAuthRoundTripper{
		Username: "testuser",
		Password: "testpass",
		FipsMode: true, // <<< FIPS ON
		Next:     mockNext,
	}
	initialReq, _ := http.NewRequest("GET", "http://mock.test/protected", nil) // Use mock host
	// Server offers SHA-256
	challengeHeader := `Digest realm="TestRealm", qop="auth", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41", algorithm=SHA-256`
	mockFunc := func(calls *int) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			*calls++
			if *calls == 1 {
				return newMockDigestResponse(http.StatusUnauthorized, http.Header{"Www-Authenticate": {challengeHeader}}, "Unauthorized"), nil
			} else if *calls == 2 {
				auth := req.Header.Get("Authorization")
				require.NotEmpty(t, auth)
				assert.Contains(t, auth, "algorithm=SHA-256") // Check SHA-256 was used
				assert.Contains(t, auth, "qop=auth")
				return newMockDigestResponse(http.StatusOK, nil, "Success Body"), nil
			}
			return nil, fmt.Errorf("too many calls")
		}
	}
	callCount := 0
	mockNext.RoundTripFunc = mockFunc(&callCount)

	finalResp, err := digestRT.RoundTrip(initialReq)

	require.NoError(t, err)
	require.NotNil(t, finalResp)
	assert.Equal(t, http.StatusOK, finalResp.StatusCode)
	assert.Equal(t, 2, callCount)
}


func TestDigestAuthRoundTripper_Fail_No_Supported_Algo(t *testing.T) {
	mockNext := &mockNextRoundTripper{}
	digestRT := &DigestAuthRoundTripper{
		Username: "testuser",
		Password: "testpass",
		FipsMode: false, // FIPS OFF
		Next:     mockNext,
	}
	initialReq, _ := http.NewRequest("GET", "http://mock.test/protected", nil) // Use mock host
	// Server offers only an unsupported algorithm
	challengeHeader := `Digest realm="TestRealm", qop="auth", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41", algorithm=UNKNOWN-ALG`
	callCount := 0
	mockNext.RoundTripFunc = func(req *http.Request) (*http.Response, error) {
		callCount++
		if callCount == 1 {
			return newMockDigestResponse(http.StatusUnauthorized, http.Header{"Www-Authenticate": {challengeHeader}}, "Unauthorized"), nil
		}
		t.Fatalf("mockNextRoundTripper called unexpectedly (%d times)", callCount)
		return nil, fmt.Errorf("too many calls")
	}

	finalResp, err := digestRT.RoundTrip(initialReq)

	require.Error(t, err)
	assert.Nil(t, finalResp)
	assert.ErrorIs(t, err, ErrDigestUnsupported, "Expected unsupported algorithm error")
	assert.Contains(t, err.Error(), "server offered 'UNKNOWN-ALG'")
	assert.Equal(t, 1, callCount)
}


func TestDigestAuthRoundTripper_AuthInt_With_Body(t *testing.T) {
	mockNext := &mockNextRoundTripper{}
	digestRT := &DigestAuthRoundTripper{
		Username: "testuser",
		Password: "testpass",
		FipsMode: false,
		Next:     mockNext,
	}
	reqBody := `{"hello":"world"}`
	initialReq, _ := http.NewRequest("POST", "http://mock.test/protected", strings.NewReader(reqBody)) // Use mock host
	initialReq.Header.Set("Content-Type", "application/json")
    // Crucially, set GetBody for the test request so the RT can re-read it for auth-int
    initialReq.GetBody = func() (io.ReadCloser, error) {
        return io.NopCloser(strings.NewReader(reqBody)), nil
    }
    initialReq.ContentLength = int64(len(reqBody))


	// Server offers auth-int
	challengeHeader := `Digest realm="TestRealm", qop="auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41", algorithm=MD5`
	mockFunc := func(calls *int) func(req *http.Request) (*http.Response, error) {
		return func(req *http.Request) (*http.Response, error) {
			*calls++
			if *calls == 1 {
				// Ensure first request has body
				bodyBytes, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				req.Body.Close()
                req.Body = io.NopCloser(bytes.NewReader(bodyBytes)) // Restore body
				assert.Equal(t, reqBody, string(bodyBytes))
				return newMockDigestResponse(http.StatusUnauthorized, http.Header{"Www-Authenticate": {challengeHeader}}, "Unauthorized"), nil
			} else if *calls == 2 {
				// Ensure second request also has body and correct auth header
				bodyBytes, err := io.ReadAll(req.Body)
                require.NoError(t, err)
				req.Body.Close()
				assert.Equal(t, reqBody, string(bodyBytes))

				auth := req.Header.Get("Authorization")
				require.NotEmpty(t, auth)
				assert.Contains(t, auth, "algorithm=MD5")
				assert.Contains(t, auth, "qop=auth-int") // Check auth-int was used
				return newMockDigestResponse(http.StatusOK, nil, "Success Body"), nil
			}
			return nil, fmt.Errorf("too many calls")
		}
	}
	callCount := 0
	mockNext.RoundTripFunc = mockFunc(&callCount)

	finalResp, err := digestRT.RoundTrip(initialReq)

	require.NoError(t, err)
	require.NotNil(t, finalResp)
	assert.Equal(t, http.StatusOK, finalResp.StatusCode)
	assert.Equal(t, 2, callCount)
}


// Test cases inherited from previous implementation, ensure they still work
func TestDigestAuthRoundTripper_Non401(t *testing.T) {
	mockNext := &mockNextRoundTripper{}
	digestRT := &DigestAuthRoundTripper{Next: mockNext}
	initialReq, _ := http.NewRequest("GET", "http://mock.test/public", nil) // Use mock host
	mockResponse := newMockDigestResponse(http.StatusOK, nil, "Public Content")
	mockNext.RoundTripFunc = func(req *http.Request) (*http.Response, error) { return mockResponse, nil }
	finalResp, err := digestRT.RoundTrip(initialReq)
	require.NoError(t, err)
	assert.Same(t, mockResponse, finalResp)
	require.Len(t, mockNext.Requests, 1)
}

func TestDigestAuthRoundTripper_401NotDigest(t *testing.T) {
	mockNext := &mockNextRoundTripper{}
	digestRT := &DigestAuthRoundTripper{Next: mockNext}
	initialReq, _ := http.NewRequest("GET", "http://mock.test/basicauth", nil) // Use mock host
	mockResponse := newMockDigestResponse(http.StatusUnauthorized, http.Header{"Www-Authenticate": {"Basic realm=Test"}}, "Unauthorized")
	mockNext.RoundTripFunc = func(req *http.Request) (*http.Response, error) { return mockResponse, nil }
	finalResp, err := digestRT.RoundTrip(initialReq)
	require.NoError(t, err)
	assert.Same(t, mockResponse, finalResp)
	require.Len(t, mockNext.Requests, 1)
}

func TestDigestAuthRoundTripper_ErrorOnFirstRequest(t *testing.T) {
	mockNext := &mockNextRoundTripper{}
	digestRT := &DigestAuthRoundTripper{Next: mockNext}
	initialReq, _ := http.NewRequest("GET", "http://mock.test/error", nil) // Use mock host
	expectedErr := errors.New("network error")
	mockNext.RoundTripFunc = func(req *http.Request) (*http.Response, error) { return nil, expectedErr }
	finalResp, err := digestRT.RoundTrip(initialReq)
	require.ErrorIs(t, err, expectedErr)
	assert.Nil(t, finalResp)
	require.Len(t, mockNext.Requests, 1)
}

func TestDigestAuthRoundTripper_ErrorOnSecondRequest(t *testing.T) {
	mockNext := &mockNextRoundTripper{}
	digestRT := &DigestAuthRoundTripper{Username: "u", Password: "p", Next: mockNext}
	initialReq, _ := http.NewRequest("GET", "http://mock.test/error2", nil) // Use mock host
	expectedErr := errors.New("server error on auth")
	challengeHeader := `Digest realm="Test", qop="auth", nonce="abc", opaque="123"`
	callCount := 0
	mockNext.RoundTripFunc = func(req *http.Request) (*http.Response, error) {
		callCount++
		if callCount == 1 { return newMockDigestResponse(http.StatusUnauthorized, http.Header{"Www-Authenticate": {challengeHeader}}, "Unauthorized"), nil }
		return nil, expectedErr
	}
	finalResp, err := digestRT.RoundTrip(initialReq)
	require.ErrorIs(t, err, expectedErr)
	assert.Nil(t, finalResp)
	assert.Equal(t, 2, callCount)
	require.Len(t, mockNext.Requests, 2)
}
