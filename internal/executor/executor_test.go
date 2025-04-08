package executor

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"api-tool/internal/config"
	"api-tool/internal/logging"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mocking Infrastructure ---
// NOTE: Mocks (mockRoundTripper, newMockClient, newMockResponse) are defined
// in pagination_test.go within the same package to avoid redeclaration.

// --- Test Functions ---

func TestExecuteRequest_RetryLogic(t *testing.T) {
	logging.SetLevel(logging.Debug) // Enable debug logs for test visibility
	originalSleeper := DefaultSleep // Store original sleeper
	t.Cleanup(func() {
		logging.SetLevel(logging.Info) // Restore default log level
		DefaultSleep = originalSleeper // Restore original sleeper function
	})

	testURL := "http://retry.test/data"
	baseRetryCfg := config.RetryConfig{
		MaxAttempts:   3,
		Backoff:       1, // 1 second backoff for tests
		ExcludeErrors: []int{400, 404},
	}

	// sleepCalls slice declared outside the loop, accessible by mockSleep closure
	var sleepCalls []time.Duration
	mockSleep := func(d time.Duration) {
		// This closure captures and modifies the outer sleepCalls slice
		sleepCalls = append(sleepCalls, d)
	}
	// Inject mock sleeper globally for the duration of this test function run
	DefaultSleep = mockSleep

	tests := []struct {
		name             string
		retryCfg         config.RetryConfig
		mockResponses    []*http.Response
		mockErrors       []error
		body             string
		expectedStatus   int
		expectedBody     string
		expectError      bool
		errorContains    string
		expectedAttempts int
		expectedSleeps   []time.Duration // Use empty slice {} for no expected sleeps
	}{
		{
			name:             "Success First Try",
			retryCfg:         baseRetryCfg,
			mockResponses:    []*http.Response{newMockResponse(200, nil, "OK")},
			expectedStatus:   200,
			expectedBody:     "OK",
			expectError:      false,
			expectedAttempts: 1,
			expectedSleeps:   []time.Duration{}, // Expect empty slice, not nil
		},
		{
			name:             "Retry on 503 then Success",
			retryCfg:         baseRetryCfg,
			mockResponses:    []*http.Response{newMockResponse(503, nil, "Retry"), newMockResponse(200, nil, "OK")},
			expectedStatus:   200,
			expectedBody:     "OK",
			expectError:      false,
			expectedAttempts: 2,
			expectedSleeps:   []time.Duration{1 * time.Second},
		},
		{
			name:             "Retry on 500 Hits Max Attempts",
			retryCfg:         baseRetryCfg,
			mockResponses:    []*http.Response{newMockResponse(500, nil, "Fail1"), newMockResponse(500, nil, "Fail2"), newMockResponse(500, nil, "Fail3")},
			expectError:      true,
			errorContains:    "received retryable status code 500",
			expectedAttempts: 3,
			expectedSleeps:   []time.Duration{1 * time.Second, 1 * time.Second},
		},
		{
			name:             "No Retry on Excluded Code 400",
			retryCfg:         baseRetryCfg,
			mockResponses:    []*http.Response{newMockResponse(400, nil, "Bad Request")},
			expectedStatus:   400,
			expectedBody:     "Bad Request",
			expectError:      false,
			expectedAttempts: 1,
			expectedSleeps:   []time.Duration{}, // Expect empty slice
		},
		{
			name:             "No Retry on Excluded Code 404",
			retryCfg:         baseRetryCfg,
			mockResponses:    []*http.Response{newMockResponse(404, nil, "Not Found")},
			expectedStatus:   404,
			expectedBody:     "Not Found",
			expectError:      false,
			expectedAttempts: 1,
			expectedSleeps:   []time.Duration{}, // Expect empty slice
		},
		{
			name:             "Retry on Network Error then Success",
			retryCfg:         baseRetryCfg,
			mockErrors:       []error{errors.New("connection refused"), nil},
			mockResponses:    []*http.Response{nil, newMockResponse(200, nil, "OK")}, // Need placeholder for mock alignment
			expectedStatus:   200,
			expectedBody:     "OK",
			expectError:      false,
			expectedAttempts: 2,
			expectedSleeps:   []time.Duration{1 * time.Second},
		},
		{
			name:             "Retry on Network Error Hits Max Attempts",
			retryCfg:         baseRetryCfg,
			mockErrors:       []error{errors.New("net err 1"), errors.New("net err 2"), errors.New("net err 3")},
			expectError:      true,
			errorContains:    "net err 3", // Last error should be reported
			expectedAttempts: 3,
			expectedSleeps:   []time.Duration{1 * time.Second, 1 * time.Second},
		},
		{
			name:             "POST Request Body Resent on Retry",
			retryCfg:         baseRetryCfg,
			body:             `{"value": "test"}`,
			mockResponses:    []*http.Response{newMockResponse(500, nil, "Fail"), newMockResponse(200, nil, "OK")},
			expectedStatus:   200,
			expectedBody:     "OK",
			expectError:      false,
			expectedAttempts: 2,
			expectedSleeps:   []time.Duration{1 * time.Second},
		},
		{
			name:             "Zero Max Attempts (Effectively 1)",
			retryCfg:         config.RetryConfig{MaxAttempts: 0, Backoff: 1}, // MaxAttempts <= 0 means 1 attempt
			mockResponses:    []*http.Response{newMockResponse(500, nil, "Fail")},
			expectError:      true,
			errorContains:    "received retryable status code 500",
			expectedAttempts: 1,
			expectedSleeps:   []time.Duration{}, // Expect empty slice
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// *** Reset sleepCalls to an empty slice for each subtest ***
			sleepCalls = []time.Duration{}

			// Use helpers defined in pagination_test.go
			client, transport := newMockClient(t, tt.mockResponses, tt.mockErrors)
			require.NotNil(t, client, "newMockClient returned nil client")
			require.NotNil(t, transport, "newMockClient returned nil transport")

			// Prepare Request
			method := "GET"
			var reqBody io.Reader
			var getBody func() (io.ReadCloser, error)
			if tt.body != "" {
				method = "POST"
				bodyBytes := []byte(tt.body)
				reqBody = bytes.NewReader(bodyBytes)
				getBody = func() (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(bodyBytes)), nil
				}
			}
			req, err := http.NewRequest(method, testURL, reqBody)
			require.NoError(t, err)
			if getBody != nil {
				req.GetBody = getBody // Ensure request body can be re-read by ExecuteRequest
				req.ContentLength = int64(len(tt.body))
			}

			// Execute the function under test
			resp, bodyBytes, err := ExecuteRequest(client, req, "none", nil, tt.retryCfg, logging.Debug)

			// --- Assertions ---
			assert.Equal(t, tt.expectedAttempts, transport.callCount, "Unexpected number of attempts")
			// Use assert.Equal directly, now that reset creates an empty slice, not nil
			assert.Equal(t, tt.expectedSleeps, sleepCalls, "Unexpected sleep calls")

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, resp) // Expect nil response on final error
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				assert.Equal(t, tt.expectedStatus, resp.StatusCode)
				assert.Equal(t, tt.expectedBody, string(bodyBytes))

				// Verify request body was potentially sent multiple times if applicable
				if tt.body != "" {
					require.Equal(t, tt.expectedAttempts, len(transport.requests), "Number of captured requests doesn't match attempts")
					for i, sentReq := range transport.requests {
						var sentBodyBytes []byte
						var readErr error
						// Safely read the body from the captured request (prefer GetBody)
						if sentReq.GetBody != nil {
							bodyCloser, gbErr := sentReq.GetBody()
							require.NoError(t, gbErr, "GetBody failed on captured request %d", i+1)
							sentBodyBytes, readErr = io.ReadAll(bodyCloser)
							bodyCloser.Close()
						} else if sentReq.Body != nil {
							// Fallback if GetBody wasn't set on the captured request somehow
							sentBodyBytes, readErr = io.ReadAll(sentReq.Body)
							sentReq.Body.Close()
						}
						require.NoError(t, readErr, "Failed reading body of captured request %d", i+1)
						assert.Equal(t, tt.body, string(sentBodyBytes), "Request body mismatch on attempt %d", i+1)
					}
				}
			}
		})
	}
}

func TestExtractHeaderValue(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Content-Type": []string{"application/json; charset=utf-8"},
			"Link":         []string{`<http://test.com/page=2>; rel="next", <http://test.com/page=1>; rel="first"`},
			"X-Request-Id": []string{"req-123abc456"},
			"Empty-Header": []string{""}, // Header present but empty
		},
	}
	tests := []struct {
		name          string
		expression    string
		expectedVal   string
		expectError   bool
		errorContains string // Check for this substring in the error
	}{
		{"Simple Match", "header:Content-Type:(.*);", "application/json", false, ""},
		{"Match Mime Type", `header:Content-Type:^([^;]+)`, "application/json", false, ""},
		{"Match Charset", `header:Content-Type:charset=([a-z0-9-]+)`, "utf-8", false, ""},
		{"Link Header Next URL", `header:Link:<([^>]+)>; rel="next"`, "http://test.com/page=2", false, ""},
		{"Request ID", `header:X-Request-Id:(req-\w+)`, "req-123abc456", false, ""},
		{"Header Not Found", `header:Missing-Header:(.*)`, "", true, "header 'Missing-Header' not found"},
		// Corrected errorContains for these cases
		{"Regex No Match", `header:Content-Type:(image/\w+)`, "", true, "did not match or capture a group"},
		{"Regex No Capture Group", `header:Content-Type:application/json`, "", true, "did not match or capture a group"},
		{"Invalid Regex", `header:Content-Type:([a-z`, "", true, "invalid regex pattern"},
		{"Invalid Format No Regex", `header:Content-Type`, "", true, "invalid header extraction expression format (missing regex)"},
		{"Invalid Format No Header Name", `header::(.*)`, "", true, "invalid header extraction expression format (empty header name or regex)"},
		{"Invalid Format No Header Prefix", `Content-Type:(.*)`, "", true, "invalid header extraction expression format"},
		{"Empty Header Value Match", `header:Empty-Header:(.*)`, "", false, ""}, // Regex `(.*)` matches empty string
		{"Empty Header Value No Match", `header:Empty-Header:(.+)`, "", true, "did not match or capture a group"}, // Regex `(.+)` requires at least one char
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualVal, err := ExtractHeaderValue(resp, tt.expression)
			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					// Use Contains for more robustness against minor error message variations
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedVal, actualVal)
			}
		})
	}
}