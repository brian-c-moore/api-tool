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

var (
	_ = json.Marshal
	_ = url.Parse
)

// ============================================ Mocking Infrastructure ============================================

type mockRoundTripper struct {
	responses []*http.Response
	requests  []*http.Request
	errors    []error
	callCount int
	t         *testing.T
	sleepFunc func(time.Duration)
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	reqClone, _ := copyRequest(req)
	m.requests = append(m.requests, reqClone)

	callIdx := m.callCount
	m.callCount++

	if len(m.errors) > callIdx && m.errors[callIdx] != nil {
		return nil, m.errors[callIdx]
	}

	if len(m.responses) > callIdx && m.responses[callIdx] != nil {
		resp := m.responses[callIdx]
		if resp.Body != nil {
			if bodyStr, ok := getMockResponseBody(resp); ok {
				resp.Body = io.NopCloser(strings.NewReader(bodyStr))
			} else {
				m.t.Logf("Warning: mockRoundTripper: Could not reset mock response body for call %d.", callIdx)
			}
		} else {
			resp.Body = nil
		}
		if resp.Request == nil {
			resp.Request = reqClone
		}
		return resp, nil
	}

	m.t.Errorf("mockRoundTripper: received unexpected request #%d: %s %s", m.callCount, req.Method, req.URL.String())
	return nil, fmt.Errorf("mockRoundTripper: unexpected request #%d", m.callCount)
}

type contextKey struct{ name string }

var originalBodyKey = &contextKey{"originalBody"}

func getMockResponseBody(resp *http.Response) (string, bool) {
	if resp == nil || resp.Request == nil || resp.Request.Context() == nil {
		return "", false
	}
	bodyVal := resp.Request.Context().Value(originalBodyKey)
	bodyStr, ok := bodyVal.(string)
	return bodyStr, ok
}

func newMockClient(t *testing.T, responses []*http.Response, errors []error) (*http.Client, *mockRoundTripper) {
	transport := &mockRoundTripper{
		responses: responses,
		errors:    errors,
		t:         t,
		sleepFunc: time.Sleep,
	}
	client := &http.Client{
		Transport: transport,
	}
	return client, transport
}

func newMockResponse(statusCode int, headers http.Header, body string) *http.Response {
	if headers == nil {
		headers = make(http.Header)
	}
	if body != "" && headers.Get("Content-Type") == "" && (strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[")) {
		headers.Set("Content-Type", "application/json")
	}
	dummyReq, _ := http.NewRequest("GET", "http://dummy.com", nil)
	ctx := context.WithValue(dummyReq.Context(), originalBodyKey, body)
	dummyReq = dummyReq.WithContext(ctx)
	return &http.Response{
		StatusCode: statusCode,
		Header:     headers,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    dummyReq,
	}
}

func newInitialTestRequest(method, urlStr string, body string) *http.Request {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, urlStr, bodyReader)
	if body != "" {
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(body)), nil
		}
		if method != "GET" && method != "" {
			if req.Header.Get("Content-Type") == "" {
				req.Header.Set("Content-Type", "application/json")
			}
			req.ContentLength = int64(len(body))
		}
	}
	return req
}

func readBodyBytesForTest(t *testing.T, source interface{}) []byte {
	t.Helper()
	var bodyReader io.ReadCloser
	var isRequest bool
	var originalReq *http.Request

	switch v := source.(type) {
	case *http.Request:
		originalReq = v
		if v == nil || v.Body == nil {
			return nil
		}
		isRequest = true
		if v.GetBody != nil {
			var err error
			bodyReader, err = v.GetBody()
			require.NoError(t, err, "Failed GetBody in readBodyBytesForTest for Request")
		} else {
			bodyReader = v.Body
		}
	case *http.Response:
		if v == nil || v.Body == nil {
			return nil
		}
		bodyReader = v.Body
	default:
		t.Fatalf("Unsupported type for readBodyBytesForTest: %T", source)
		return nil
	}

	bytesVal, err := io.ReadAll(bodyReader)
	bodyReader.Close()
	require.NoError(t, err, "Failed to read body bytes for test")

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
				originalReq.Body = bodyReadCloser
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

type expectedRequestDetail struct {
	Method   string
	URL      string
	BodyJSON string
}

// ============================================ Test Functions ============================================

func TestHandleOffsetOrPagePagination(t *testing.T) {
	originalLogLevel := logging.GetLevel()
	logging.SetLevel(logging.Debug)
	defer logging.SetLevel(originalLogLevel)

	testCases := []struct {
		name               string
		pagCfg             config.PaginationConfig
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
			name: "Offset Stop By Total",
			pagCfg: config.PaginationConfig{
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
				{Method: "GET", URL: "http://test.com/items?skip=2&take=2"},
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
				SizeParam:    "s",
			},
			initialReq:  newInitialTestRequest("GET", "http://test.com/data?p=1&s=2", ""),
			initialResp: newMockResponse(200, nil, `{ "data": [{"id": "a"}, {"id": "b"}] }`),
			mockResponses: []*http.Response{
				newMockResponse(200, nil, `{ "data": [{"id": "c"}, {"id": "d"}] }`),
				newMockResponse(200, nil, `{ "data": [{"id": "e"}] }`),
			},
			authType:     "none",
			expectedJSON: `[{"id":"a"},{"id":"b"},{"id":"c"},{"id":"d"},{"id":"e"}]`,
			expectError:  false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://test.com/data?p=2&s=2"},
				{Method: "GET", URL: "http://test.com/data?p=3&s=2"},
			},
		},
		{
			name: "Offset in POST Body Nested",
			pagCfg: config.PaginationConfig{
				Type:          "offset",
				Strategy:      "offset",
				Limit:         2,
				OffsetParam:   "startOffset",
				LimitParam:    "count",
				ParamLocation: "body",
				BodyPath:      "query.options",
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
			},
			initialReq:    newInitialTestRequest("GET", "http://test.com/items?offset=0&limit=2", ""),
			initialResp:   newMockResponse(200, nil, `{"items": [{"id": 1}, {"id": 2}], "total": 4}`),
			mockResponses: []*http.Response{},
			mockErrors:    []error{fmt.Errorf("network timeout")},
			authType:      "none",
			expectedJSON:  `[{"id":1},{"id":2}]`,
			expectError:   true,
			errorContains: "network timeout",
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://test.com/items?limit=2&offset=2"},
			},
		},
		{
			name: "Offset Stop By Empty Results",
			pagCfg: config.PaginationConfig{
				Type:         "offset",
				Strategy:     "offset",
				Limit:        5,
				ResultsField: "data",
			},
			initialReq:    newInitialTestRequest("GET", "http://test.com/data?limit=5&offset=0", ""),
			initialResp:   newMockResponse(200, nil, `{"data": [{"id": 1}, {"id": 2}]}`),
			mockResponses: []*http.Response{newMockResponse(200, nil, `{"data": []}`)},
			authType:      "none",
			expectedJSON:  `[{"id":1},{"id":2}]`,
			expectError:   false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://test.com/data?limit=5&offset=2"},
			},
		},
		{
			name: "Offset Stop By Header Total",
			pagCfg: config.PaginationConfig{
				Type:         "offset",
				Strategy:     "offset",
				Limit:        1,
				ResultsField: "items",
				TotalHeader:  "X-Total",
				OffsetParam:  "skip",
				LimitParam:   "take",
			},
			initialReq:    newInitialTestRequest("GET", "http://test.com/items?skip=0&take=1", ""),
			initialResp:   newMockResponse(200, http.Header{"X-Total": {"2"}}, `{"items": [{"id": "a"}]}`),
			mockResponses: []*http.Response{newMockResponse(200, http.Header{"X-Total": {"2"}}, `{"items": [{"id": "b"}]}`)},
			authType:      "none",
			expectedJSON:  `[{"id":"a"},{"id":"b"}]`,
			expectError:   false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://test.com/items?skip=1&take=1"},
			},
		},
		{
			name: "Offset Stop By MaxPages",
			pagCfg: config.PaginationConfig{
				Type:         "offset",
				Limit:        2,
				ResultsField: "items",
				MaxPages:     2,
			},
			initialReq:  newInitialTestRequest("GET", "http://test.com/items?limit=2&offset=0", ""),
			initialResp: newMockResponse(200, nil, `{"items": [1, 2]}`),
			mockResponses: []*http.Response{
				newMockResponse(200, nil, `{"items": [3, 4]}`),
			},
			authType:     "none",
			expectedJSON: `[1,2,3,4]`,
			expectError:  false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://test.com/items?limit=2&offset=2"},
			},
		},
		{
			name: "Offset MaxPages Not Hit Due To Other Stop",
			pagCfg: config.PaginationConfig{
				Type:         "offset",
				Limit:        2,
				ResultsField: "items",
				TotalField:   "total",
				MaxPages:     5,
			},
			initialReq:    newInitialTestRequest("GET", "http://test.com/items?limit=2&offset=0", ""),
			initialResp:   newMockResponse(200, nil, `{"items": [1, 2], "total": 3}`),
			mockResponses: []*http.Response{newMockResponse(200, nil, `{"items": [3], "total": 3}`)},
			authType:      "none",
			expectedJSON:  `[1,2,3]`,
			expectError:   false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://test.com/items?limit=2&offset=2"},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			endpointCfg := config.EndpointConfig{Pagination: &tc.pagCfg}
			mockClient, _ := newMockClient(t, tc.mockResponses, tc.mockErrors)
			dummyCreds := map[string]string{}
			dummyRetry := config.RetryConfig{MaxAttempts: 1}

			initialReqForRun, err := copyRequest(tc.initialReq)
			require.NoError(t, err)
			initialRespForRun := newMockResponse(tc.initialResp.StatusCode, tc.initialResp.Header, string(readBodyBytesForTest(t, tc.initialResp)))
			initialRespForRun.Request = initialReqForRun
			initialBodyBytesForRun := readBodyBytesForTest(t, initialRespForRun)

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

			if tc.expectError {
				require.Error(t, actualErr)
				if tc.errorContains != "" {
					assert.Contains(t, actualErr.Error(), tc.errorContains)
				}
				if tc.expectedJSON != "" {
					assert.JSONEq(t, tc.expectedJSON, actualJSON)
				}
			} else {
				require.NoError(t, actualErr)
				assert.JSONEq(t, tc.expectedJSON, actualJSON)
			}

			mockTransport, ok := mockClient.Transport.(*mockRoundTripper)
			require.True(t, ok)
			require.Equal(t, len(tc.expectedReqDetails), len(mockTransport.requests))

			for i, expectedDetail := range tc.expectedReqDetails {
				require.Less(t, i, len(mockTransport.requests))
				actualReq := mockTransport.requests[i]
				assert.Equal(t, expectedDetail.Method, actualReq.Method)
				assert.Equal(t, expectedDetail.URL, actualReq.URL.String())
				if expectedDetail.BodyJSON != "" {
					actualBodyBytes := readBodyBytesForTest(t, actualReq)
					assert.JSONEq(t, expectedDetail.BodyJSON, string(actualBodyBytes))
				} else {
					if actualReq.Body != nil {
						actualBodyBytes := readBodyBytesForTest(t, actualReq)
						assert.Empty(t, actualBodyBytes)
					} else {
						assert.Nil(t, actualReq.Body)
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
		pagCfg             config.PaginationConfig
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
				NextField:    "paging.nextCursor",
			},
			initialReq:  newInitialTestRequest("GET", "http://test.com/data", ""),
			initialResp: newMockResponse(200, nil, `{"data": [1.0], "paging": {"nextCursor": "cursorA"}}`),
			mockResponses: []*http.Response{
				newMockResponse(200, nil, `{"data": [3.0], "paging": {"nextCursor": "cursorB"}}`),
				newMockResponse(200, nil, `{"data": [5.0], "paging": {}}`),
			},
			authType:     "none",
			expectedJSON: `[1.0,3.0,5.0]`,
			expectError:  false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://test.com/data?cursor=cursorA"},
				{Method: "GET", URL: "http://test.com/data?cursor=cursorB"},
			},
		},
		{
			name: "Cursor in Header, Query Usage Custom Param",
			pagCfg: config.PaginationConfig{
				Type:         "cursor",
				ResultsField: "results",
				NextHeader:   "X-Next-Token",
				CursorParam:  "next_token",
			},
			initialReq:  newInitialTestRequest("GET", "http://test.com/results", ""),
			initialResp: newMockResponse(200, http.Header{"X-Next-Token": {"tok1"}}, `{"results": ["a"]}`),
			mockResponses: []*http.Response{
				newMockResponse(200, http.Header{"X-Next-Token": {"tok2"}}, `{"results": ["b"]}`),
				newMockResponse(200, http.Header{}, `{"results": ["c"]}`),
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
				NextField:       "nextLink",
				CursorUsageMode: "url",
			},
			initialReq:  newInitialTestRequest("GET", "http://base.com/api/v1/stuff", ""),
			initialResp: newMockResponse(200, nil, `{"values": [10], "nextLink": "http://base.com/api/v1/stuff?page=2"}`),
			mockResponses: []*http.Response{
				newMockResponse(200, nil, `{"values": [20], "nextLink": "/api/v1/stuff?page=3"}`),
				newMockResponse(200, nil, `{"values": [30], "nextLink": null}`),
			},
			authType:     "none",
			expectedJSON: `[10,20,30]`,
			expectError:  false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://base.com/api/v1/stuff?page=2"},
				{Method: "GET", URL: "http://base.com/api/v1/stuff?page=3"},
			},
		},
		{
			name: "Cursor in POST Body",
			pagCfg: config.PaginationConfig{
				Type:            "cursor",
				ResultsField:    "items",
				NextField:       "nextToken",
				CursorUsageMode: "body",
				CursorParam:     "pageToken",
				BodyPath:        "pagingInfo",
			},
			initialReq:  newInitialTestRequest("POST", "http://test.com/search", `{"query": "stuff", "pagingInfo": {}}`),
			initialResp: newMockResponse(200, nil, `{"items": ["x"], "nextToken": "cursor1"}`),
			mockResponses: []*http.Response{
				newMockResponse(200, nil, `{"items": ["y"], "nextToken": "cursor2"}`),
				newMockResponse(200, nil, `{"items": ["z"], "nextToken": null}`),
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
				Type:         "cursor",
				ResultsField: "data",
				NextField:    "paging.nextCursor",
			},
			initialReq:    newInitialTestRequest("GET", "http://test.com/data", ""),
			initialResp:   newMockResponse(200, nil, `{"data": [1.0], "paging": {"nextCursor": "cursorA"}}`),
			mockResponses: []*http.Response{},
			mockErrors:    []error{fmt.Errorf("internal server error")},
			authType:      "none",
			expectedJSON:  `[1.0]`,
			expectError:   true,
			errorContains: "internal server error",
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://test.com/data?cursor=cursorA"},
			},
		},
		{
			name: "Cursor Stop by MaxPages",
			pagCfg: config.PaginationConfig{
				Type:         "cursor",
				ResultsField: "data",
				NextField:    "next",
				MaxPages:     3,
			},
			initialReq:  newInitialTestRequest("GET", "http://test.com/data", ""),
			initialResp: newMockResponse(200, nil, `{"data": [0], "next": "c1"}`),
			mockResponses: []*http.Response{
				newMockResponse(200, nil, `{"data": [1], "next": "c2"}`),
				newMockResponse(200, nil, `{"data": [2], "next": "c3"}`),
			},
			authType:     "none",
			expectedJSON: `[0,1,2]`,
			expectError:  false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://test.com/data?cursor=c1"},
				{Method: "GET", URL: "http://test.com/data?cursor=c2"},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			endpointCfg := config.EndpointConfig{Pagination: &tc.pagCfg}
			mockClient, _ := newMockClient(t, tc.mockResponses, tc.mockErrors)
			dummyCreds := map[string]string{}
			dummyRetry := config.RetryConfig{MaxAttempts: 1}

			initialReqForRun, err := copyRequest(tc.initialReq)
			require.NoError(t, err)
			initialRespForRun := newMockResponse(tc.initialResp.StatusCode, tc.initialResp.Header, string(readBodyBytesForTest(t, tc.initialResp)))
			initialRespForRun.Request = initialReqForRun
			initialBodyBytesForRun := readBodyBytesForTest(t, initialRespForRun)

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

			if tc.expectError {
				require.Error(t, actualErr)
				if tc.errorContains != "" {
					assert.Contains(t, actualErr.Error(), tc.errorContains)
				}
				if tc.expectedJSON != "" {
					assert.JSONEq(t, tc.expectedJSON, actualJSON)
				}
			} else {
				require.NoError(t, actualErr)
				assert.JSONEq(t, tc.expectedJSON, actualJSON)
			}

			mockTransport, ok := mockClient.Transport.(*mockRoundTripper)
			require.True(t, ok)
			require.Equal(t, len(tc.expectedReqDetails), len(mockTransport.requests))

			for i, expectedDetail := range tc.expectedReqDetails {
				require.Less(t, i, len(mockTransport.requests))
				actualReq := mockTransport.requests[i]
				assert.Equal(t, expectedDetail.Method, actualReq.Method)
				assert.Equal(t, expectedDetail.URL, actualReq.URL.String())
				if expectedDetail.BodyJSON != "" {
					actualBodyBytes := readBodyBytesForTest(t, actualReq)
					assert.JSONEq(t, expectedDetail.BodyJSON, string(actualBodyBytes))
				} else {
					if actualReq.Body != nil {
						actualBodyBytes := readBodyBytesForTest(t, actualReq)
						assert.Empty(t, actualBodyBytes)
					} else {
						assert.Nil(t, actualReq.Body)
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
		pagCfg             config.PaginationConfig
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
				newMockResponse(200, http.Header{}, `{"items": [3.0]}`),
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
				newMockResponse(200, http.Header{"Link": {`<http://api.example.com/data?p=1>; rel="prev", <http://api.example.com/data?p=2>; rel="first"`}}, `{"data": ["b"]}`),
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
			initialResp: newMockResponse(200, http.Header{"Link": {`</v2/records?cursor=abc>; rel="next"`}}, `{"records": [1.0]}`),
			mockResponses: []*http.Response{
				newMockResponse(200, http.Header{}, `{"records": [2.0]}`),
			},
			authType:     "none",
			expectedJSON: `[1.0,2.0]`,
			expectError:  false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://api.example.com/v2/records?cursor=abc"},
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
			expectedJSON:  `[1.0]`,
			expectError:   true,
			errorContains: "access denied",
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://api.example.com/items?page=2"},
			},
		},
		{
			name: "Link Header Stop By MaxPages",
			pagCfg: config.PaginationConfig{
				Type:         "link_header",
				ResultsField: "items",
				MaxPages:     2,
			},
			initialReq:  newInitialTestRequest("GET", "http://api.example.com/items", ""),
			initialResp: newMockResponse(200, http.Header{"Link": {`</items?page=2>; rel="next"`}}, `{"items": [0]}`),
			mockResponses: []*http.Response{
				newMockResponse(200, http.Header{"Link": {`</items?page=3>; rel="next"`}}, `{"items": [1]}`),
			},
			authType:     "none",
			expectedJSON: `[0, 1]`,
			expectError:  false,
			expectedReqDetails: []expectedRequestDetail{
				{Method: "GET", URL: "http://api.example.com/items?page=2"},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			endpointCfg := config.EndpointConfig{Pagination: &tc.pagCfg}
			mockClient, _ := newMockClient(t, tc.mockResponses, tc.mockErrors)
			dummyCreds := map[string]string{}
			dummyRetry := config.RetryConfig{MaxAttempts: 1}

			initialReqForRun, err := copyRequest(tc.initialReq)
			require.NoError(t, err)
			initialRespForRun := newMockResponse(tc.initialResp.StatusCode, tc.initialResp.Header, string(readBodyBytesForTest(t, tc.initialResp)))
			initialRespForRun.Request = initialReqForRun
			initialBodyBytesForRun := readBodyBytesForTest(t, initialRespForRun)

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

			if tc.expectError {
				require.Error(t, actualErr)
				if tc.errorContains != "" {
					assert.Contains(t, actualErr.Error(), tc.errorContains)
				}
				if tc.expectedJSON != "" {
					assert.JSONEq(t, tc.expectedJSON, actualJSON)
				}
			} else {
				require.NoError(t, actualErr)
				assert.JSONEq(t, tc.expectedJSON, actualJSON)
			}

			mockTransport, ok := mockClient.Transport.(*mockRoundTripper)
			require.True(t, ok)
			require.Equal(t, len(tc.expectedReqDetails), len(mockTransport.requests))

			for i, expectedDetail := range tc.expectedReqDetails {
				require.Less(t, i, len(mockTransport.requests))
				actualReq := mockTransport.requests[i]
				assert.Equal(t, expectedDetail.Method, actualReq.Method)
				assert.Equal(t, expectedDetail.URL, actualReq.URL.String())
				if actualReq.Body != nil {
					actualBodyBytes := readBodyBytesForTest(t, actualReq)
					assert.Empty(t, actualBodyBytes)
				} else {
					assert.Nil(t, actualReq.Body)
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
		{name: "Link with different rel types (should ignore)", headers: http.Header{"Link": {`<http://test.com/prev>; rel="previous", <http://test.com/next>; rel="next page"`}}, expectedURL: "", expectedFound: false},
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
		{"Base URL ends no slash", func() *url.URL { u, _ := url.Parse("http://noslash.com/api"); return u }(), "path", "http://noslash.com/path", false},
		{"Nil Base URL", nil, "/relative/path", "/relative/path", false},
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
	logging.SetLevel(logging.Debug)
	defer logging.SetLevel(originalLogLevel)

	testCases := []struct {
		name              string
		initialData       map[string]interface{}
		path              string
		expectedMapJSON   string
		expectedFinalData string
		expectError       bool
		modifyAction      func(targetMap map[string]interface{}, t *testing.T)
		expectedErrorMsg  string
	}{
		{
			name:              "Empty Path",
			initialData:       map[string]interface{}{"a": 1.0},
			path:              "",
			expectedMapJSON:   `{"a":1.0}`,
			expectedFinalData: `{"a":1.0}`,
			expectError:       false,
		},
		{
			name:        "Simple Path Exists - Get Target",
			initialData: map[string]interface{}{"a": map[string]interface{}{"b": map[string]interface{}{"original": true}}},
			path:        "a.b",
			expectedMapJSON:   `{"original":true}`,
			expectedFinalData: `{"a":{"b":{"original":true,"c":3.0}}}`,
			expectError:       false,
			modifyAction: func(targetMap map[string]interface{}, t *testing.T) {
				require.NotNil(t, targetMap)
				targetMap["c"] = 3.0
			},
		},
		{
			name:        "Create Simple Path",
			initialData: map[string]interface{}{},
			path:        "new.path",
			expectedMapJSON:   `{}`,
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
			expectedMapJSON:   `{}`,
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
			path:             "a.b",
			expectError:      true,
			expectedErrorMsg: "intermediate field 'a' in path 'a.b' is not a map",
		},
		{
			name:             "Path Collides with Non-Map (Final)",
			initialData:      map[string]interface{}{"a": map[string]interface{}{"b": 123}},
			path:             "a.b",
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

				actualMapBytes, _ := json.Marshal(targetMap)
				assert.JSONEq(t, tc.expectedMapJSON, string(actualMapBytes))

				if tc.modifyAction != nil {
					tc.modifyAction(targetMap, t)
				}

				finalDataBytes, _ := json.Marshal(dataCopy)
				assert.JSONEq(t, tc.expectedFinalData, string(finalDataBytes))
			}
		})
	}
}


// TestModifyRequestForInitialPage tests the exported function for adding initial params.
func TestModifyRequestForInitialPage(t *testing.T) {
	originalLogLevel := logging.GetLevel()
	logging.SetLevel(logging.Debug)
	defer logging.SetLevel(originalLogLevel)

	testCases := []struct {
		name          string
		pagCfg        config.PaginationConfig
		initialReq    *http.Request
		expectedURL   string
		expectedBody  string // Expect JSON string
		expectError   bool
		errorContains string
	}{
		{
			name: "Offset Type - Query Params",
			pagCfg: config.PaginationConfig{
				Type:        "offset",
				Strategy:    "offset", // Explicitly offset
				Limit:       10,
				OffsetParam: "offset",
				LimitParam:  "limit",
			},
			initialReq:  newInitialTestRequest("GET", "http://test.com/items?other=val", ""),
			expectedURL: "http://test.com/items?limit=10&offset=0&other=val",
			expectError: false,
		},
		{
			name: "Page Type - Query Params",
			pagCfg: config.PaginationConfig{
				Type:      "page",
				Strategy:  "page", // Explicitly page
				Limit:     5,
				StartPage: 1,
				PageParam: "p",
				SizeParam: "s",
			},
			initialReq:  newInitialTestRequest("GET", "http://test.com/data", ""),
			expectedURL: "http://test.com/data?p=1&s=5",
			expectError: false,
		},
		{
			name: "Offset Type - Body Params - No Existing Body",
			pagCfg: config.PaginationConfig{
				Type:          "offset",
				Strategy:      "offset",
				Limit:         20,
				OffsetParam:   "off",
				LimitParam:    "lim",
				ParamLocation: "body",
				BodyPath:      "params",
			},
			initialReq:    newInitialTestRequest("POST", "http://test.com/search", ""), // No initial body
			expectedURL:   "http://test.com/search",
			expectedBody:  `{"params":{"lim":20,"off":0}}`, // Expect params nested under "params"
			expectError:   false,
		},
		{
			name: "Page Type - Body Params - Merge with Existing Body",
			pagCfg: config.PaginationConfig{
				Type:          "page",
				Strategy:      "page",
				Limit:         15,
				StartPage:     2, // Start page 2
				PageParam:     "page_num",
				SizeParam:     "page_size",
				ParamLocation: "body",
				// No BodyPath means root level
			},
			initialReq:    newInitialTestRequest("POST", "http://test.com/query", `{"filter": "active", "sort": "name"}`), // Existing body
			expectedURL:   "http://test.com/query",
			expectedBody:  `{"filter":"active","page_num":2,"page_size":15,"sort":"name"}`, // Merged params
			expectError:   false,
		},
		{
			name: "Invalid Type (Cursor)",
			pagCfg: config.PaginationConfig{
				Type: "cursor", // Wrong type for this function
			},
			initialReq:  newInitialTestRequest("GET", "http://test.com/items", ""),
			expectError: true,
			errorContains: "only supports offset/page types",
		},
		{
			name: "Body Params - Invalid Body JSON",
			pagCfg: config.PaginationConfig{
				Type:          "offset",
				Limit:         10,
				ParamLocation: "body",
			},
			initialReq:    newInitialTestRequest("POST", "http://test.com/items", `{"malformed":`), // Invalid JSON
			expectError:   true,
			errorContains: "failed parse request body JSON",
		},
		{
			name: "Body Params - Invalid BodyPath",
			pagCfg: config.PaginationConfig{
				Type:          "offset",
				Limit:         10,
				ParamLocation: "body",
				BodyPath:      "a..b", // Invalid path
			},
			initialReq:    newInitialTestRequest("POST", "http://test.com/items", `{}`),
			expectError:   true,
			errorContains: "path cannot contain empty segments",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqCopy, err := copyRequest(tc.initialReq) // Work on a copy
			require.NoError(t, err, "Failed to copy request")

			err = ModifyRequestForInitialPage(&tc.pagCfg, reqCopy)

			if tc.expectError {
				require.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedURL, reqCopy.URL.String(), "URL mismatch")

				if tc.pagCfg.ParamLocation == "body" {
					require.NotNil(t, reqCopy.Body, "Request body should not be nil")
					actualBodyBytes, readErr := io.ReadAll(reqCopy.Body)
					reqCopy.Body.Close() // Close the read body
					require.NoError(t, readErr)
					assert.JSONEq(t, tc.expectedBody, string(actualBodyBytes), "Request body JSON mismatch")
					// Verify GetBody was set correctly
					require.NotNil(t, reqCopy.GetBody, "GetBody should be set after body modification")
					gbReader, gbErr := reqCopy.GetBody()
					require.NoError(t, gbErr)
					gbBytes, gbReadErr := io.ReadAll(gbReader)
					gbReader.Close()
					require.NoError(t, gbReadErr)
					assert.JSONEq(t, tc.expectedBody, string(gbBytes), "GetBody content mismatch")

				} else {
					// For query params, body should be unchanged
					if tc.initialReq.Body != nil {
						initialBodyBytes, _ := io.ReadAll(tc.initialReq.Body)
						tc.initialReq.Body = io.NopCloser(bytes.NewReader(initialBodyBytes)) // Reset original
						actualBodyBytes, _ := io.ReadAll(reqCopy.Body)
						reqCopy.Body = io.NopCloser(bytes.NewReader(actualBodyBytes)) // Reset copy
						assert.Equal(t, initialBodyBytes, actualBodyBytes, "Body should not change for query params")
					} else {
						assert.Nil(t, reqCopy.Body, "Body should remain nil for query params")
					}
				}
			}
		})
	}
}