// internal/executor/pagination_test.go
package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"api-tool/internal/config"
	"api-tool/internal/logging"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Dummy variables prevent "imported and not used" errors for standard packages
// sometimes needed indirectly by testify or other operations.
var (
	_ = json.Marshal
	_ = url.Parse
)

// ============================================ Mocking Infrastructure ============================================

// mockRoundTripper simulates HTTP responses for pagination tests by implementing http.RoundTripper.
type mockRoundTripper struct {
	responses []*http.Response
	requests  []*http.Request
	errors    []error
	callCount int
	t         *testing.T
	sleepFunc func(time.Duration) // Added field for mockable sleep
}

// RoundTrip intercepts requests made by the http.Client and returns mock responses/errors.
func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Store a clone for verification. Make sure GetBody is copied if present.
	reqClone, _ := copyRequest(req) // Use our copyRequest to handle GetBody correctly
	m.requests = append(m.requests, reqClone)

	callIdx := m.callCount
	m.callCount++

	// Check for a configured error for this specific call index.
	if len(m.errors) > callIdx && m.errors[callIdx] != nil {
		return nil, m.errors[callIdx]
	}

	// Check for a configured response for this specific call index.
	if len(m.responses) > callIdx && m.responses[callIdx] != nil {
		resp := m.responses[callIdx]

		// Ensure the response body can be read multiple times by resetting it.
		if resp.Body != nil {
			if bodyStr, ok := getMockResponseBody(resp); ok {
				// Create a new reader from the original string content for this call.
				resp.Body = io.NopCloser(strings.NewReader(bodyStr))
			} else {
				// Log if unable to reset - body might only be readable once.
				m.t.Logf("Warning: mockRoundTripper: Could not reset mock response body for call %d.", callIdx)
			}
		} else {
			// Explicitly set to nil if no body was intended.
			resp.Body = nil
		}
		// Ensure the mock response is linked to the incoming request for context propagation
		if resp.Request == nil {
			resp.Request = reqClone // Link if not already set
		}
		return resp, nil // Return the prepared mock response.
	}

	// If no response or error was configured for this call index.
	m.t.Errorf("mockRoundTripper: received unexpected request #%d: %s %s", m.callCount, req.Method, req.URL.String())
	return nil, fmt.Errorf("mockRoundTripper: unexpected request #%d", m.callCount)
}

// contextKey defines a key type for storing values in context.
type contextKey struct{ name string }

// originalBodyKey is used to associate the original body string with a mock response via context.
var originalBodyKey = &contextKey{"originalBody"}

// getMockResponseBody retrieves the original body string stored via context.
func getMockResponseBody(resp *http.Response) (string, bool) {
	if resp == nil || resp.Request == nil || resp.Request.Context() == nil {
		return "", false
	}
	bodyVal := resp.Request.Context().Value(originalBodyKey)
	bodyStr, ok := bodyVal.(string)
	return bodyStr, ok
}

// newMockClient creates an http.Client configured with the mockRoundTripper.
func newMockClient(t *testing.T, responses []*http.Response, errors []error) (*http.Client, *mockRoundTripper) { // Returns 2 values
	transport := &mockRoundTripper{
		responses: responses,
		errors:    errors,
		t:         t,
		sleepFunc: time.Sleep, // Initialize sleepFunc
	}
	client := &http.Client{
		Transport: transport,
	}
	return client, transport // Returns 2 values
}

// newMockResponse creates an *http.Response suitable for mocking.
func newMockResponse(statusCode int, headers http.Header, body string) *http.Response {
	if headers == nil {
		headers = make(http.Header)
	}
	// Auto-set Content-Type for JSON-like bodies if not already set
	if body != "" && headers.Get("Content-Type") == "" && (strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[")) {
		headers.Set("Content-Type", "application/json")
	}
	// Create a dummy request to attach context holding the original body
	dummyReq, _ := http.NewRequest("GET", "http://dummy.com", nil)
	ctx := context.WithValue(dummyReq.Context(), originalBodyKey, body)
	dummyReq = dummyReq.WithContext(ctx)
	return &http.Response{
		StatusCode: statusCode,
		Header:     headers,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    dummyReq, // Associate the request with context
	}
}

// newInitialTestRequest creates a basic *http.Request for initializing tests.
func newInitialTestRequest(method, urlStr string, body string) *http.Request {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, urlStr, bodyReader)
	if body != "" {
		// Set GetBody so it can be re-read
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(body)), nil
		}
		// Auto-set Content-Type and Length for non-GET requests with body
		if method != "GET" && method != "" {
			if req.Header.Get("Content-Type") == "" {
				req.Header.Set("Content-Type", "application/json") // Assume JSON for tests
			}
			req.ContentLength = int64(len(body))
		}
	}
	return req
}

// readBodyBytesForTest safely reads body bytes from a request or response for test assertions.
func readBodyBytesForTest(t *testing.T, source interface{}) []byte {
	t.Helper()
	var bodyReader io.ReadCloser
	var isRequest bool
	var originalReq *http.Request

	// Determine the source type and get the body reader.
	switch v := source.(type) {
	case *http.Request:
		originalReq = v // Keep reference to original request
		if v == nil || v.Body == nil {
			return nil // Nothing to read if request or body is nil.
		}
		isRequest = true
		// Prefer GetBody to allow re-reading.
		if v.GetBody != nil {
			var err error
			bodyReader, err = v.GetBody()
			require.NoError(t, err, "Failed GetBody in readBodyBytesForTest for Request")
		} else {
			// Fallback: Read directly, consuming the original body.
			bodyReader = v.Body
		}
	case *http.Response: // Correct placement inside the switch
		if v == nil || v.Body == nil {
			return nil // Nothing to read if response or body is nil.
		}
		bodyReader = v.Body
	default:
		// Fail the test if an unsupported type is passed.
		t.Fatalf("Unsupported type for readBodyBytesForTest: %T", source)
		return nil // Unreachable, but needed for compiler.
	} // Correct placement of switch closing brace

	// Read all bytes from the obtained reader.
	bytesVal, err := io.ReadAll(bodyReader)
	// *** FIX: Ensure the reader is closed directly ***
	bodyReader.Close() // Directly close the io.ReadCloser
	require.NoError(t, err, "Failed to read body bytes for test")

	// --- Reset the body reader on the original source object ---
	if resp, ok := source.(*http.Response); ok {
		if bodyStr, okGet := getMockResponseBody(resp); okGet {
			resp.Body = io.NopCloser(strings.NewReader(bodyStr))
		} else {
			resp.Body = io.NopCloser(bytes.NewReader(bytesVal))
		}
	} else if isRequest && originalReq != nil {
		if originalReq.GetBody != nil {
			bodyReadCloser, resetErr := originalReq.GetBody()
			if resetErr == nil {
				originalReq.Body = bodyReadCloser // Reset the main Body reader
			} else {
				t.Logf("Warning: Could not reset request body after reading for test: %v", resetErr)
				originalReq.Body = io.NopCloser(bytes.NewReader(bytesVal))
			}
		} else {
			originalReq.Body = io.NopCloser(bytes.NewReader(bytesVal))
		}
	}

	return bytesVal
}

// expectedRequestDetail defines the structure for verifying subsequent requests in tests.
type expectedRequestDetail struct {
	Method   string
	URL      string
	BodyJSON string // Use JSON string for body comparison
}

// ============================================ Test Functions ============================================

func TestHandleOffsetOrPagePagination(t *testing.T) {
	// Use Debug level for tests to see detailed logs
	originalLogLevel := logging.GetLevel()
	logging.SetLevel(logging.Debug)
	defer logging.SetLevel(originalLogLevel) // Restore original level after test

	testCases := []struct {
		name               string
		pagCfg             config.PaginationConfig // Use value type here, defaults applied in HandlePagination
		initialReq         *http.Request
		initialResp        *http.Response
		mockResponses      []*http.Response
		mockErrors         []error
		authType           string
		expectedJSON       string
		expectError        bool
		errorContains      string
		expectedReqDetails []expectedRequestDetail // Details of subsequent requests
	}{
		{
			name: "Offset Stop By Total",
			pagCfg: config.PaginationConfig{ // Explicitly set Type for clarity
				Type:         "offset",
				Strategy:     "offset",
				Limit:        2,
				ResultsField: "items",
				TotalField:   "total",
				OffsetParam:  "skip",
				LimitParam:   "take",
			},
			initialReq:    newInitialTestRequest("GET", "http://test.com/items?skip=0&take=2", ""),
			initialResp:   newMockResponse(200, nil, `{"items": [{"id": 1}, {"id": 2}], "total": 3}`),
			mockResponses: []*http.Response{newMockResponse(200, nil, `{"items": [{"id": 3}], "total": 3}`)},
			authType:      "none",
			expectedJSON:  `[{"id":1},{"id":2},{"id":3}]`,
			expectError:   false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://test.com/items?skip=2&take=2"}, // Expect corrected URL
			},
		},
		{
			name: "Page Stop By Results Less Than Limit",
			pagCfg: config.PaginationConfig{
				Type:         "page",
				Strategy:     "page",
				Limit:        2,
				ResultsField: "data",
				PageParam:    "p",
				SizeParam:    "s", // Maps internally to LimitParam if LimitParam is empty
			},
			initialReq:  newInitialTestRequest("GET", "http://test.com/data?p=1&s=2", ""),
			initialResp: newMockResponse(200, nil, `{ "data": [{"id": "a"}, {"id": "b"}] }`),
			mockResponses: []*http.Response{
				newMockResponse(200, nil, `{ "data": [{"id": "c"}, {"id": "d"}] }`),
				newMockResponse(200, nil, `{ "data": [{"id": "e"}] }`), // Last page has fewer items
			},
			authType:     "none",
			expectedJSON: `[{"id":"a"},{"id":"b"},{"id":"c"},{"id":"d"},{"id":"e"}]`,
			expectError:  false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://test.com/data?p=2&s=2"}, // Expect page 2
				{Method: "GET", URL: "http://test.com/data?p=3&s=2"}, // Expect page 3
			},
		},
		{
			name: "Offset in POST Body Nested",
			pagCfg: config.PaginationConfig{
				Type:          "offset", // Must specify type
				Strategy:      "offset",
				Limit:         2,
				OffsetParam:   "startOffset",
				LimitParam:    "count", // Using 'count' as limit param name
				ParamLocation: "body",
				BodyPath:      "query.options", // Nested path
				ResultsField:  "response.results",
				TotalField:    "response.totalRecords",
			},
			initialReq: newInitialTestRequest("POST", "http://test.com/analysis", `{"type": "vuln","query": { "tool": "details", "options": { "startOffset": 0, "count": 2 }}}`),
			initialResp: newMockResponse(200, nil, `{"response": { "results": [{"ip": "1.1.1.1"}, {"ip": "2.2.2.2"}], "totalRecords": 3 }}`),
			mockResponses: []*http.Response{
				newMockResponse(200, nil, `{"response": { "results": [{"ip": "3.3.3.3"}], "totalRecords": 3 }}`),
			},
			authType:     "none",
			expectedJSON: `[{"ip":"1.1.1.1"},{"ip":"2.2.2.2"},{"ip":"3.3.3.3"}]`,
			expectError:  false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "POST", URL: "http://test.com/analysis", BodyJSON: `{"type":"vuln","query":{"tool":"details","options":{"count":2,"startOffset":2}}}`},
			},
		},
		{
			name: "Offset Error on Page 2",
			pagCfg: config.PaginationConfig{
				Type:         "offset",
				Strategy:     "offset",
				Limit:        2,
				ResultsField: "items",
				TotalField:   "total",
			}, // Uses default offset/limit param names
			initialReq:    newInitialTestRequest("GET", "http://test.com/items?offset=0&limit=2", ""),
			initialResp:   newMockResponse(200, nil, `{"items": [{"id": 1}, {"id": 2}], "total": 4}`),
			mockResponses: []*http.Response{}, // No successful response for page 2
			mockErrors:    []error{fmt.Errorf("network timeout")},
			authType:      "none",
			expectedJSON:  `[{"id":1},{"id":2}]`, // Expect partial results
			expectError:   true,
			errorContains: "network timeout",
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://test.com/items?limit=2&offset=2"}, // Expect request for offset 2
			},
		},
		{
			name: "Offset Stop By Empty Results",
			pagCfg: config.PaginationConfig{
				Type:         "offset",
				Strategy:     "offset",
				Limit:        5,
				ResultsField: "data",
			}, // No total field specified
			initialReq:    newInitialTestRequest("GET", "http://test.com/data?limit=5&offset=0", ""),
			initialResp:   newMockResponse(200, nil, `{"data": [{"id": 1}, {"id": 2}]}`), // Fewer than limit initially
			mockResponses: []*http.Response{newMockResponse(200, nil, `{"data": []}`)},    // Next page is empty
			authType:      "none",
			expectedJSON:  `[{"id":1},{"id":2}]`,
			expectError:   false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://test.com/data?limit=5&offset=2"}, // Expect request for offset 2
			},
		},
		{
			name: "Offset Stop By Header Total",
			pagCfg: config.PaginationConfig{
				Type:        "offset",
				Strategy:    "offset",
				Limit:       1,
				ResultsField: "items",
				TotalHeader: "X-Total", // Total comes from header
				OffsetParam: "skip",
				LimitParam:  "take",
			},
			initialReq:    newInitialTestRequest("GET", "http://test.com/items?skip=0&take=1", ""),
			initialResp:   newMockResponse(200, http.Header{"X-Total": {"2"}}, `{"items": [{"id": "a"}]}`),
			mockResponses: []*http.Response{newMockResponse(200, http.Header{"X-Total": {"2"}}, `{"items": [{"id": "b"}]}`)},
			authType:      "none",
			expectedJSON:  `[{"id":"a"},{"id":"b"}]`,
			expectError:   false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://test.com/items?skip=1&take=1"}, // Expect skip=1
			},
		},
		{
			name: "Offset Stop By MaxPages",
			pagCfg: config.PaginationConfig{
				Type:         "offset",
				Limit:        2,
				ResultsField: "items",
				MaxPages:     2, // <<< Stop after fetching 2 pages (page index 0 and 1)
			},
			initialReq:  newInitialTestRequest("GET", "http://test.com/items?limit=2&offset=0", ""),
			initialResp: newMockResponse(200, nil, `{"items": [1, 2]}`), // Page 1 (index 0)
			mockResponses: []*http.Response{
				newMockResponse(200, nil, `{"items": [3, 4]}`), // Page 2 (index 1) - Should be fetched
			},
			authType:     "none",
			expectedJSON: `[1,2,3,4]`, // Only results from first 2 pages
			expectError:  false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://test.com/items?limit=2&offset=2"}, // Request for Page 2
			},
		},
		{
			name: "Offset MaxPages Not Hit Due To Other Stop",
			pagCfg: config.PaginationConfig{
				Type:         "offset",
				Limit:        2,
				ResultsField: "items",
				TotalField:   "total",
				MaxPages:     5, // High MaxPages
			},
			initialReq:    newInitialTestRequest("GET", "http://test.com/items?limit=2&offset=0", ""),
			initialResp:   newMockResponse(200, nil, `{"items": [1, 2], "total": 3}`), // Total is 3
			mockResponses: []*http.Response{newMockResponse(200, nil, `{"items": [3], "total": 3}`)}, // Last item
			authType:      "none",
			expectedJSON:  `[1,2,3]`, // Stops because total reached
			expectError:   false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://test.com/items?limit=2&offset=2"}, // Request for last item
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// --- Setup ---
			endpointCfg := config.EndpointConfig{Pagination: &tc.pagCfg}
			// Correctly assign both return values, ignore transport if not needed immediately
			mockClient, _ := newMockClient(t, tc.mockResponses, tc.mockErrors) // <-- Corrected Assignment
			dummyCreds := map[string]string{}
			dummyRetry := config.RetryConfig{MaxAttempts: 1}

			initialReqForRun, err := copyRequest(tc.initialReq)
			require.NoError(t, err, "Failed to copy initial request for run")
			initialRespForRun := newMockResponse(tc.initialResp.StatusCode, tc.initialResp.Header, string(readBodyBytesForTest(t, tc.initialResp)))
			initialRespForRun.Request = initialReqForRun
			initialBodyBytesForRun := readBodyBytesForTest(t, initialRespForRun)

			// --- Execute ---
			actualJSON, actualErr := HandlePagination(
				mockClient,
				initialReqForRun,
				endpointCfg,
				initialRespForRun,
				initialBodyBytesForRun,
				tc.authType,
				dummyCreds,
				dummyRetry,
				logging.GetLevel(),
			)

			// --- Assert ---
			if tc.expectError {
				require.Error(t, actualErr)
				if tc.errorContains != "" {
					assert.Contains(t, actualErr.Error(), tc.errorContains)
				}
				if tc.expectedJSON != "" {
					assert.JSONEq(t, tc.expectedJSON, actualJSON, "Partial JSON results mismatch on error")
				}
			} else {
				require.NoError(t, actualErr)
				assert.JSONEq(t, tc.expectedJSON, actualJSON, "Final JSON results mismatch")
			}

			// Verify the subsequent requests made
			mockTransport, ok := mockClient.Transport.(*mockRoundTripper) // Retrieve transport from client
			require.True(t, ok, "Could not get mockRoundTripper from client")
			require.Equal(t, len(tc.expectedReqDetails), len(mockTransport.requests), "Mismatch in expected number of subsequent requests made")

			for i, expectedDetail := range tc.expectedReqDetails {
				require.Less(t, i, len(mockTransport.requests))
				actualReq := mockTransport.requests[i]
				assert.Equal(t, expectedDetail.Method, actualReq.Method, "Request #%d: Method mismatch", i+1)
				assert.Equal(t, expectedDetail.URL, actualReq.URL.String(), "Request #%d: URL mismatch", i+1)
				if expectedDetail.BodyJSON != "" {
					actualBodyBytes := readBodyBytesForTest(t, actualReq)
					assert.JSONEq(t, expectedDetail.BodyJSON, string(actualBodyBytes), "Request #%d: Body JSON mismatch", i+1)
				} else {
					if actualReq.Body != nil {
						actualBodyBytes := readBodyBytesForTest(t, actualReq)
						assert.Empty(t, actualBodyBytes, "Request #%d: Expected no body, but found one with content", i+1)
					} else {
						assert.Nil(t, actualReq.Body, "Request #%d: Expected no body, but found one", i+1)
					}
				}
			}
		})
	}
}

func TestHandleCursorPagination(t *testing.T) {
	originalLogLevel := logging.GetLevel()
	logging.SetLevel(logging.Debug)
	defer logging.SetLevel(originalLogLevel)

	testCases := []struct {
		name               string
		pagCfg             config.PaginationConfig // Value type here
		initialReq         *http.Request
		initialResp        *http.Response
		mockResponses      []*http.Response
		mockErrors         []error
		authType           string
		expectedJSON       string
		expectError        bool
		errorContains      string
		expectedReqDetails []expectedRequestDetail
	}{
		{
			name: "Cursor in Body Field, Query Usage",
			pagCfg: config.PaginationConfig{
				Type:         "cursor",
				ResultsField: "data",
				NextField:    "paging.nextCursor", // gjson path to cursor in response body
			},
			initialReq:  newInitialTestRequest("GET", "http://test.com/data", ""),
			initialResp: newMockResponse(200, nil, `{"data": [1.0], "paging": {"nextCursor": "cursorA"}}`),
			mockResponses: []*http.Response{
				newMockResponse(200, nil, `{"data": [3.0], "paging": {"nextCursor": "cursorB"}}`),
				newMockResponse(200, nil, `{"data": [5.0], "paging": {}}`), // No nextCursor means stop
			},
			authType:     "none",
			expectedJSON: `[1.0,3.0,5.0]`,
			expectError:  false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://test.com/data?cursor=cursorA"}, // Default cursor param name
				{Method: "GET", URL: "http://test.com/data?cursor=cursorB"},
			},
		},
		{
			name: "Cursor in Header, Query Usage Custom Param",
			pagCfg: config.PaginationConfig{
				Type:         "cursor",
				ResultsField: "results",
				NextHeader:   "X-Next-Token", // Cursor is in this header
				CursorParam: "next_token", // Custom query parameter name
			},
			initialReq:  newInitialTestRequest("GET", "http://test.com/results", ""),
			initialResp: newMockResponse(200, http.Header{"X-Next-Token": {"tok1"}}, `{"results": ["a"]}`),
			mockResponses: []*http.Response{
				newMockResponse(200, http.Header{"X-Next-Token": {"tok2"}}, `{"results": ["b"]}`),
				newMockResponse(200, http.Header{}, `{"results": ["c"]}`), // No header means stop
			},
			authType:     "none",
			expectedJSON: `["a","b","c"]`,
			expectError:  false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://test.com/results?next_token=tok1"},
				{Method: "GET", URL: "http://test.com/results?next_token=tok2"},
			},
		},
		{
			name: "Cursor is Full URL",
			pagCfg: config.PaginationConfig{
				Type:            "cursor",
				ResultsField:    "values",
				NextField:       "nextLink", // Cursor is the value of this field
				CursorUsageMode: "url",      // Treat the cursor as the next URL
			},
			initialReq:  newInitialTestRequest("GET", "http://base.com/api/v1/stuff", ""),
			initialResp: newMockResponse(200, nil, `{"values": [10], "nextLink": "http://base.com/api/v1/stuff?page=2"}`),
			mockResponses: []*http.Response{
				newMockResponse(200, nil, `{"values": [20], "nextLink": "/api/v1/stuff?page=3"}`), // Relative URL
				newMockResponse(200, nil, `{"values": [30], "nextLink": null}`),                  // Null nextLink means stop
			},
			authType:     "none",
			expectedJSON: `[10,20,30]`,
			expectError:  false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://base.com/api/v1/stuff?page=2"}, // Absolute URL used
				{Method: "GET", URL: "http://base.com/api/v1/stuff?page=3"}, // Relative URL resolved correctly
			},
		},
		{
			name: "Cursor in POST Body",
			pagCfg: config.PaginationConfig{
				Type:            "cursor",
				ResultsField:    "items",
				NextField:       "nextToken",
				CursorUsageMode: "body",       // Put cursor back in the body
				CursorParam:     "pageToken",  // Name of the field for the cursor in the *next* request body
				BodyPath:        "pagingInfo", // Put pageToken inside this nested object
			},
			initialReq:  newInitialTestRequest("POST", "http://test.com/search", `{"query": "stuff", "pagingInfo": {}}`),
			initialResp: newMockResponse(200, nil, `{"items": ["x"], "nextToken": "cursor1"}`),
			mockResponses: []*http.Response{
				newMockResponse(200, nil, `{"items": ["y"], "nextToken": "cursor2"}`),
				newMockResponse(200, nil, `{"items": ["z"], "nextToken": null}`), // Null stops pagination
			},
			authType:     "none",
			expectedJSON: `["x","y","z"]`,
			expectError:  false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "POST", URL: "http://test.com/search", BodyJSON: `{"query":"stuff","pagingInfo":{"pageToken":"cursor1"}}`},
				{Method: "POST", URL: "http://test.com/search", BodyJSON: `{"query":"stuff","pagingInfo":{"pageToken":"cursor2"}}`},
			},
		},
		{
			name: "Cursor Error on Page 2",
			pagCfg: config.PaginationConfig{
				Type:       "cursor",
				ResultsField: "data",
				NextField:  "paging.nextCursor",
			},
			initialReq:    newInitialTestRequest("GET", "http://test.com/data", ""),
			initialResp:   newMockResponse(200, nil, `{"data": [1.0], "paging": {"nextCursor": "cursorA"}}`),
			mockResponses: []*http.Response{}, // No successful response
			mockErrors:    []error{fmt.Errorf("internal server error")},
			authType:      "none",
			expectedJSON:  `[1.0]`, // Partial results
			expectError:   true,
			errorContains: "internal server error",
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://test.com/data?cursor=cursorA"}, // Expect request for cursor A
			},
		},
		{
			name: "Cursor Stop by MaxPages",
			pagCfg: config.PaginationConfig{
				Type:         "cursor",
				ResultsField: "data",
				NextField:    "next",
				MaxPages:     3, // Stop after fetching page index 0, 1, 2
			},
			initialReq:  newInitialTestRequest("GET", "http://test.com/data", ""),
			initialResp: newMockResponse(200, nil, `{"data": [0], "next": "c1"}`), // Page 1 (idx 0)
			mockResponses: []*http.Response{
				newMockResponse(200, nil, `{"data": [1], "next": "c2"}`), // Page 2 (idx 1)
				newMockResponse(200, nil, `{"data": [2], "next": "c3"}`), // Page 3 (idx 2) - Should be fetched
			},
			authType:     "none",
			expectedJSON: `[0,1,2]`, // Results from first 3 pages
			expectError:  false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://test.com/data?cursor=c1"}, // Request page 2
				{Method: "GET", URL: "http://test.com/data?cursor=c2"}, // Request page 3
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// --- Setup ---
			endpointCfg := config.EndpointConfig{Pagination: &tc.pagCfg}
			// Correctly assign both return values, ignore transport if not needed immediately
			mockClient, _ := newMockClient(t, tc.mockResponses, tc.mockErrors) // <-- Corrected Assignment
			dummyCreds := map[string]string{}
			dummyRetry := config.RetryConfig{MaxAttempts: 1}

			initialReqForRun, err := copyRequest(tc.initialReq)
			require.NoError(t, err, "Failed to copy initial request for run")
			initialRespForRun := newMockResponse(tc.initialResp.StatusCode, tc.initialResp.Header, string(readBodyBytesForTest(t, tc.initialResp)))
			initialRespForRun.Request = initialReqForRun
			initialBodyBytesForRun := readBodyBytesForTest(t, initialRespForRun)

			// --- Execute ---
			actualJSON, actualErr := HandlePagination(
				mockClient,
				initialReqForRun,
				endpointCfg,
				initialRespForRun,
				initialBodyBytesForRun,
				tc.authType,
				dummyCreds,
				dummyRetry,
				logging.GetLevel(),
			)

			// --- Assert ---
			if tc.expectError {
				require.Error(t, actualErr)
				if tc.errorContains != "" {
					assert.Contains(t, actualErr.Error(), tc.errorContains)
				}
				if tc.expectedJSON != "" {
					assert.JSONEq(t, tc.expectedJSON, actualJSON, "Partial JSON results mismatch on error")
				}
			} else {
				require.NoError(t, actualErr)
				assert.JSONEq(t, tc.expectedJSON, actualJSON, "Final JSON results mismatch")
			}

			mockTransport, ok := mockClient.Transport.(*mockRoundTripper) // Retrieve transport from client
			require.True(t, ok, "Could not get mockRoundTripper from client")
			require.Equal(t, len(tc.expectedReqDetails), len(mockTransport.requests), "Mismatch in expected number of subsequent requests made")

			for i, expectedDetail := range tc.expectedReqDetails {
				require.Less(t, i, len(mockTransport.requests))
				actualReq := mockTransport.requests[i]
				assert.Equal(t, expectedDetail.Method, actualReq.Method, "Request #%d: Method mismatch", i+1)
				assert.Equal(t, expectedDetail.URL, actualReq.URL.String(), "Request #%d: URL mismatch", i+1)
				if expectedDetail.BodyJSON != "" {
					actualBodyBytes := readBodyBytesForTest(t, actualReq)
					assert.JSONEq(t, expectedDetail.BodyJSON, string(actualBodyBytes), "Request #%d: Body JSON mismatch", i+1)
				} else {
					if actualReq.Body != nil {
						actualBodyBytes := readBodyBytesForTest(t, actualReq)
						assert.Empty(t, actualBodyBytes, "Request #%d: Expected no body, but found one with content", i+1)
					} else {
						assert.Nil(t, actualReq.Body, "Request #%d: Expected no body, but found one", i+1)
					}
				}
			}
		})
	}
}

func TestHandleLinkHeaderPagination(t *testing.T) {
	originalLogLevel := logging.GetLevel()
	logging.SetLevel(logging.Debug)
	defer logging.SetLevel(originalLogLevel)

	testCases := []struct {
		name               string
		pagCfg             config.PaginationConfig // Value type here
		initialReq         *http.Request
		initialResp        *http.Response
		mockResponses      []*http.Response
		mockErrors         []error
		authType           string
		expectedJSON       string
		expectError        bool
		errorContains      string
		expectedReqDetails []expectedRequestDetail
	}{
		{
			name: "Simple Link Header",
			pagCfg: config.PaginationConfig{
				Type:         "link_header",
				ResultsField: "items",
			},
			initialReq:  newInitialTestRequest("GET", "http://api.example.com/items", ""),
			initialResp: newMockResponse(200, http.Header{"Link": {`<http://api.example.com/items?page=2>; rel="next"`}}, `{"items": [1.0]}`),
			mockResponses: []*http.Response{
				newMockResponse(200, http.Header{"Link": {`<http://api.example.com/items?page=3>; rel="next"`}}, `{"items": [2.0]}`),
				newMockResponse(200, http.Header{}, `{"items": [3.0]}`), // No Link header stops pagination
			},
			authType:     "none",
			expectedJSON: `[1.0,2.0,3.0]`,
			expectError:  false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://api.example.com/items?page=2"},
				{Method: "GET", URL: "http://api.example.com/items?page=3"},
			},
		},
		{
			name: "Link Header with Multiple Links",
			pagCfg: config.PaginationConfig{
				Type:         "link_header",
				ResultsField: "data",
			},
			initialReq:  newInitialTestRequest("GET", "http://api.example.com/data", ""),
			initialResp: newMockResponse(200, http.Header{"Link": {`<http://api.example.com/data?p=1>; rel="first", <http://api.example.com/data?p=2>; rel="next"`}}, `{"data": ["a"]}`),
			mockResponses: []*http.Response{
				newMockResponse(200, http.Header{"Link": {`<http://api.example.com/data?p=1>; rel="prev", <http://api.example.com/data?p=2>; rel="first"`}}, `{"data": ["b"]}`), // No next link
			},
			authType:     "none",
			expectedJSON: `["a","b"]`,
			expectError:  false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://api.example.com/data?p=2"},
			},
		},
		{
			name: "Link Header Relative URL",
			pagCfg: config.PaginationConfig{
				Type:         "link_header",
				ResultsField: "records",
			},
			initialReq:  newInitialTestRequest("GET", "http://api.example.com/v2/records", ""),
			initialResp: newMockResponse(200, http.Header{"Link": {`</v2/records?cursor=abc>; rel="next"`}}, `{"records": [1.0]}`), // Relative link
			mockResponses: []*http.Response{
				newMockResponse(200, http.Header{}, `{"records": [2.0]}`), // No link stops
			},
			authType:     "none",
			expectedJSON: `[1.0,2.0]`,
			expectError:  false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://api.example.com/v2/records?cursor=abc"}, // Correctly resolved
			},
		},
		{
			name: "Link Header Error on Page 2",
			pagCfg: config.PaginationConfig{
				Type:         "link_header",
				ResultsField: "items",
			},
			initialReq:    newInitialTestRequest("GET", "http://api.example.com/items", ""),
			initialResp:   newMockResponse(200, http.Header{"Link": {`<http://api.example.com/items?page=2>; rel="next"`}}, `{"items": [1.0]}`),
			mockResponses: []*http.Response{},
			mockErrors:    []error{fmt.Errorf("access denied")},
			authType:      "none",
			expectedJSON:  `[1.0]`, // Partial result
			expectError:   true,
			errorContains: "access denied",
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://api.example.com/items?page=2"}, // The failed request
			},
		},
		{
			name: "Link Header Stop By MaxPages",
			pagCfg: config.PaginationConfig{
				Type:         "link_header",
				ResultsField: "items",
				MaxPages:     2, // Stop after fetching page 0 and 1
			},
			initialReq:  newInitialTestRequest("GET", "http://api.example.com/items", ""),
			initialResp: newMockResponse(200, http.Header{"Link": {`</items?page=2>; rel="next"`}}, `{"items": [0]}`), // Page 1 (idx 0)
			mockResponses: []*http.Response{
				newMockResponse(200, http.Header{"Link": {`</items?page=3>; rel="next"`}}, `{"items": [1]}`), // Page 2 (idx 1) - Fetched
			},
			authType:     "none",
			expectedJSON: `[0, 1]`, // Only results from first 2 pages
			expectError:  false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://api.example.com/items?page=2"}, // Request page 2
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// --- Setup ---
			endpointCfg := config.EndpointConfig{Pagination: &tc.pagCfg}
			// Correctly assign both return values, ignore transport if not needed immediately
			mockClient, _ := newMockClient(t, tc.mockResponses, tc.mockErrors) // <-- Corrected Assignment
			dummyCreds := map[string]string{}
			dummyRetry := config.RetryConfig{MaxAttempts: 1}

			initialReqForRun, err := copyRequest(tc.initialReq)
			require.NoError(t, err, "Failed to copy initial request for run")
			initialRespForRun := newMockResponse(tc.initialResp.StatusCode, tc.initialResp.Header, string(readBodyBytesForTest(t, tc.initialResp)))
			initialRespForRun.Request = initialReqForRun
			initialBodyBytesForRun := readBodyBytesForTest(t, initialRespForRun)

			// --- Execute ---
			actualJSON, actualErr := HandlePagination(
				mockClient,
				initialReqForRun,
				endpointCfg,
				initialRespForRun,
				initialBodyBytesForRun,
				tc.authType,
				dummyCreds,
				dummyRetry,
				logging.GetLevel(),
			)

			// --- Assert ---
			if tc.expectError {
				require.Error(t, actualErr)
				if tc.errorContains != "" {
					assert.Contains(t, actualErr.Error(), tc.errorContains)
				}
				if tc.expectedJSON != "" {
					assert.JSONEq(t, tc.expectedJSON, actualJSON, "Partial JSON results mismatch on error")
				}
			} else {
				require.NoError(t, actualErr)
				assert.JSONEq(t, tc.expectedJSON, actualJSON, "Final JSON results mismatch")
			}

			mockTransport, ok := mockClient.Transport.(*mockRoundTripper) // Retrieve transport from client
			require.True(t, ok, "Could not get mockRoundTripper from client")
			require.Equal(t, len(tc.expectedReqDetails), len(mockTransport.requests), "Mismatch in expected number of subsequent requests made")

			for i, expectedDetail := range tc.expectedReqDetails {
				require.Less(t, i, len(mockTransport.requests))
				actualReq := mockTransport.requests[i]
				assert.Equal(t, expectedDetail.Method, actualReq.Method, "Request #%d: Method mismatch", i+1)
				assert.Equal(t, expectedDetail.URL, actualReq.URL.String(), "Request #%d: URL mismatch", i+1)
				// Link header pagination usually implies GET with no body
				if actualReq.Body != nil {
					actualBodyBytes := readBodyBytesForTest(t, actualReq)
					assert.Empty(t, actualBodyBytes, "Request #%d: Expected no body for Link header request, but found content", i+1)
				} else {
					assert.Nil(t, actualReq.Body, "Request #%d: Expected no body for Link header request", i+1)
				}
			}
		})
	}
}

func TestParseLinkHeader(t *testing.T) {
	testCases := []struct {
		name          string
		headers       http.Header
		expectedURL   string
		expectedFound bool
	}{
		{name: "No Link Header", headers: http.Header{}, expectedURL: "", expectedFound: false},
		{name: "Simple Next Link", headers: http.Header{"Link": {`<http://test.com/page=2>; rel="next"`}}, expectedURL: "http://test.com/page=2", expectedFound: true},
		{name: "Multiple Links Including Next", headers: http.Header{"Link": {`<http://test.com/page=1>; rel="first", <http://test.com/page=3>; rel="next", <http://test.com/page=10>; rel="last"`}}, expectedURL: "http://test.com/page=3", expectedFound: true},
		{name: "Multiple Link Headers", headers: http.Header{"Link": {`<http://test.com/page=1>; rel="first"`, `<http://test.com/page=2>; rel="next"`}}, expectedURL: "http://test.com/page=2", expectedFound: true},
		{name: "Link with different rel types (should ignore)", headers: http.Header{"Link": {`<http://test.com/prev>; rel="previous", <http://test.com/next>; rel="next page"`}}, expectedURL: "", expectedFound: false}, // "next page" is not "next"
		{name: "No next link present", headers: http.Header{"Link": {`<http://test.com/page=10>; rel="last"`}}, expectedURL: "", expectedFound: false},
		{name: "Link with quotes around rel", headers: http.Header{"Link": {`<https://api.example.com/items?page=2>; rel="next"`}}, expectedURL: "https://api.example.com/items?page=2", expectedFound: true},
		{name: "Link without quotes around known rel (should still parse)", headers: http.Header{"Link": {`<https://api.example.com/items?page=2>; rel=next`}}, expectedURL: "https://api.example.com/items?page=2", expectedFound: true},
		{name: "Link with extra spaces", headers: http.Header{"Link": {` <https://test.com/next> ;  rel = "next" `}}, expectedURL: "https://test.com/next", expectedFound: true},
		{name: "GitHub style link header", headers: http.Header{"Link": {`<https://api.github.com/user/repos?page=3&per_page=100>; rel="next", <https://api.github.com/user/repos?page=50&per_page=100>; rel="last"`}}, expectedURL: "https://api.github.com/user/repos?page=3&per_page=100", expectedFound: true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualURL, actualFound := parseLinkHeader(tc.headers)
			assert.Equal(t, tc.expectedFound, actualFound)
			assert.Equal(t, tc.expectedURL, actualURL)
		})
	}
}

func TestMakeAbsoluteURL(t *testing.T) {
	baseURL, _ := url.Parse("http://base.com/api/v1/")
	testCases := []struct {
		name        string
		originalURL *url.URL
		nextURL     string
		expected    string
		expectError bool
	}{
		{"Absolute Next URL", baseURL, "https://absolute.com/path", "https://absolute.com/path", false},
		{"Relative Path Next URL", baseURL, "items?page=2", "http://base.com/api/v1/items?page=2", false},
		{"Relative Path Parent Dir", baseURL, "../items?page=2", "http://base.com/api/items?page=2", false},
		{"Root Relative Path", baseURL, "/other/path", "http://base.com/other/path", false},
		{"Empty Next URL", baseURL, "", "http://base.com/api/v1/", false},
		{"Invalid Next URL Syntax", baseURL, ":invalid:", "", true},
		{"Base URL with Path", baseURL, "endpoint", "http://base.com/api/v1/endpoint", false},
		{"Base URL ends no slash", func() *url.URL { u, _ := url.Parse("http://noslash.com/api"); return u }(), "path", "http://noslash.com/path", false}, // ResolveReference handles this
		{"Nil Base URL", nil, "/relative/path", "/relative/path", false},                                                                                         // Relative path with nil base remains relative
		{"Nil Base URL, Absolute Next", nil, "https://absolute.com", "https://absolute.com", false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := makeAbsoluteURL(tc.originalURL, tc.nextURL)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, actual)
			}
		})
	}
}

func TestFindOrCreateTargetPath(t *testing.T) {
	originalLogLevel := logging.GetLevel()
	logging.SetLevel(logging.Debug) // Ensure debug logs if needed
	defer logging.SetLevel(originalLogLevel)

	testCases := []struct {
		name              string
		initialData       map[string]interface{}
		path              string
		expectedMapJSON   string // Expected JSON of the *returned target map*
		expectedFinalData string // Expected JSON of the *entire modified* data structure
		expectError       bool
		modifyAction      func(targetMap map[string]interface{}, t *testing.T) // Action to perform on returned map
		expectedErrorMsg  string                                                // Optional: Specific error message check
	}{
		{
			name:              "Empty Path",
			initialData:       map[string]interface{}{"a": 1.0},
			path:              "",
			expectedMapJSON:   `{"a":1.0}`, // Returns root map
			expectedFinalData: `{"a":1.0}`, // No change expected
			expectError:       false,
		},
		{
			name:        "Simple Path Exists - Get Target",
			initialData: map[string]interface{}{"a": map[string]interface{}{"b": map[string]interface{}{"original": true}}},
			path:        "a.b", // Path to the map 'b'
			// Expect the map that exists at a.b *before* modification
			expectedMapJSON:   `{"original":true}`,
			// Final state *after* test adds "c":3.0 into map 'b'
			expectedFinalData: `{"a":{"b":{"original":true,"c":3.0}}}`,
			expectError:       false,
			modifyAction: func(targetMap map[string]interface{}, t *testing.T) {
				require.NotNil(t, targetMap)
				targetMap["c"] = 3.0 // Add 'c' into the returned map 'b'
			},
		},
		{
			name:        "Create Simple Path",
			initialData: map[string]interface{}{}, // Start empty
			path:        "new.path",
			// Expect newly created empty map at 'path'
			expectedMapJSON:   `{}`,
			// Final state after test adds "value":true to the new map
			expectedFinalData: `{"new":{"path":{"value":true}}}`,
			expectError:       false,
			modifyAction: func(targetMap map[string]interface{}, t *testing.T) {
				require.NotNil(t, targetMap)
				targetMap["value"] = true
			},
		},
		{
			name:        "Create Nested Path",
			initialData: map[string]interface{}{"existing": "root"},
			path:        "a.b.c",
			// Expect newly created empty map at 'c'
			expectedMapJSON:   `{}`,
			// Final state after adding value to 'c'
			expectedFinalData: `{"existing":"root","a":{"b":{"c":{"nestedValue":123}}}}`,
			expectError:       false,
			modifyAction: func(targetMap map[string]interface{}, t *testing.T) {
				require.NotNil(t, targetMap)
				targetMap["nestedValue"] = 123
			},
		},
		{
			name:             "Path Collides with Non-Map (Intermediate)",
			initialData:      map[string]interface{}{"a": "string", "b": 123},
			path:             "a.b", // 'a' exists but is not a map
			expectError:      true,
			expectedErrorMsg: "intermediate field 'a' in path 'a.b' is not a map",
		},
		{
			name:             "Path Collides with Non-Map (Final)",
			initialData:      map[string]interface{}{"a": map[string]interface{}{"b": 123}},
			path:             "a.b", // 'b' exists but is not a map
			expectError:      true,
			expectedErrorMsg: "field 'b' at end of path 'a.b' exists but is not a map",
		},
		{
			name:             "Invalid Path - Starts with Dot",
			initialData:      map[string]interface{}{},
			path:             ".a.b",
			expectError:      true,
			expectedErrorMsg: "path cannot start with '.'",
		},
		{
			name:             "Invalid Path - Ends with Dot",
			initialData:      map[string]interface{}{},
			path:             "a.b.",
			expectError:      true,
			expectedErrorMsg: "path cannot end with '.'",
		},
		{
			name:             "Invalid Path - Double Dot",
			initialData:      map[string]interface{}{},
			path:             "a..b",
			expectError:      true,
			expectedErrorMsg: "path cannot contain empty segments ('..')",
		},
		{
			name:             "Invalid Path - Just a Dot",
			initialData:      map[string]interface{}{},
			path:             ".",
			expectError:      true,
			expectedErrorMsg: "invalid body_path: path cannot be just '.'",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Deep copy initial data to avoid modification across tests
			dataCopy := make(map[string]interface{})
			initialJSON, _ := json.Marshal(tc.initialData)
			_ = json.Unmarshal(initialJSON, &dataCopy)

			targetMap, err := findOrCreateTargetPath(dataCopy, tc.path)

			if tc.expectError {
				require.Error(t, err)
				assert.Nil(t, targetMap)
				if tc.expectedErrorMsg != "" {
					assert.Contains(t, err.Error(), tc.expectedErrorMsg)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, targetMap)

				// Verify the returned map structure *before* modification
				actualMapBytes, _ := json.Marshal(targetMap)
				assert.JSONEq(t, tc.expectedMapJSON, string(actualMapBytes), "Returned target map structure mismatch")

				// Perform modification if specified
				if tc.modifyAction != nil {
					tc.modifyAction(targetMap, t)
				}

				// Verify the final state of the *entire* data structure
				finalDataBytes, _ := json.Marshal(dataCopy)
				assert.JSONEq(t, tc.expectedFinalData, string(finalDataBytes), "Final data structure mismatch after modification")
			}
		})
	}
}