package chain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"api-tool/internal/config"
	"api-tool/internal/logging"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// --- Mocks ---
type mockHTTPClientProvider struct{ mock.Mock }

func (m *mockHTTPClientProvider) NewClient(apiCfg *config.APIConfig, authCfg *config.AuthConfig, jar http.CookieJar, fipsMode bool) (*http.Client, error) {
	args := m.Called(apiCfg, authCfg, jar, fipsMode)
	client, _ := args.Get(0).(*http.Client)
	return client, args.Error(1)
}

var _ httpClientProvider = (*mockHTTPClientProvider)(nil)

// mockRequestExecutor captures the request for later verification.
type mockRequestExecutor struct {
	mock.Mock
	mu             sync.Mutex // Protect captured requests
	CapturedReqs   []*http.Request
	CapturedBodies [][]byte // Store bodies separately as request body gets consumed
}

// Helper function to safely read request body and store it.
// Returns the bytes read and resets the body reader.
func captureAndResetBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	if r.GetBody != nil {
		// Preferred way: use GetBody
		bodyReadCloser, err := r.GetBody()
		if err != nil {
			return nil, fmt.Errorf("capture GetBody failed: %w", err)
		}
		defer bodyReadCloser.Close()
		bodyBytes, err := io.ReadAll(bodyReadCloser)
		if err != nil {
			return nil, fmt.Errorf("capture read failed: %w", err)
		}
		// No need to reset r.Body here, as GetBody provides fresh readers
		return bodyBytes, nil
	}
	// Fallback: No GetBody
	bodyBytes, err := io.ReadAll(r.Body)
	r.Body.Close() // Close original
	if err != nil {
		return nil, fmt.Errorf("capture direct read failed: %w", err)
	}
	// Reset body and set GetBody
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodyBytes)), nil
	}
	return bodyBytes, nil
}

// ExecuteRequest is the mock implementation for the requestExecutor interface.
// It captures the request details, calls the underlying mock framework for expectation matching,
// and correctly handles the response body, especially for download tests involving error readers.
func (m *mockRequestExecutor) ExecuteRequest(client *http.Client, req *http.Request, effAuth string, creds map[string]string, retry config.RetryConfig, lvl int) (*http.Response, []byte, error) {
	// Capture request and its body *before* calling the mock framework's verification.
	m.mu.Lock()
	reqMetaClone := req.Clone(context.Background())
	reqMetaClone.Body = nil // Avoid cloning body directly
	m.CapturedReqs = append(m.CapturedReqs, reqMetaClone)
	bodyBytes, _ := captureAndResetBody(req) // Capture and reset
	m.CapturedBodies = append(m.CapturedBodies, bodyBytes)
	m.mu.Unlock()

	// Call the mock framework's logic.
	args := m.Called(client, req, effAuth, creds, retry, lvl)
	resp, _ := args.Get(0).(*http.Response)
	respBodyBytes, respBodyOK := args.Get(1).([]byte) // Explicit bytes provided?
	execErr := args.Error(2)

	// Ensure the mock response body is correctly prepared.
	if resp != nil {
		if respBodyOK && respBodyBytes != nil {
			// If explicit bytes were provided, use them. This is the standard success case.
			resp.Body = io.NopCloser(bytes.NewReader(respBodyBytes))
		} else if !respBodyOK && resp.Body != nil {
			// If explicit bytes were NOT provided (respBodyBytes is nil due to args.Get(1))
			// AND resp.Body is already set (e.g., to an errorReader by the test setup),
			// THEN *keep* the existing resp.Body.
			// The runner needs the original errorReader.
			// We also ensure respBodyBytes remains nil to signal this to the runner.
			respBodyBytes = nil // Signal to runner to use resp.Body
		} else {
			// Otherwise (no explicit bytes, no existing resp.Body, or respBodyBytes was explicitly nil)
			// set to empty body.
			if respBodyBytes == nil { // Ensure it's not nil if we create it here
				respBodyBytes = []byte{}
			}
			resp.Body = io.NopCloser(bytes.NewReader(respBodyBytes))
		}
	} else {
		// No response object at all.
		respBodyBytes = nil
	}

	// Return the determined response body bytes along with response and error.
	return resp, respBodyBytes, execErr
}

func (m *mockRequestExecutor) HandlePagination(client *http.Client, req *http.Request, epCfg config.EndpointConfig, resp *http.Response, body []byte, effAuth string, creds map[string]string, retry config.RetryConfig, lvl int) (string, error) {
	args := m.Called(client, req, epCfg, resp, body, effAuth, creds, retry, lvl)
	if resp != nil && resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
	return args.String(0), args.Error(1)
}

var _ requestExecutor = (*mockRequestExecutor)(nil)

type mockJQRunner struct{ mock.Mock }

func (m *mockJQRunner) RunFilter(input []byte, jqFilter string) (string, error) {
	args := m.Called(input, jqFilter)
	return args.String(0), args.Error(1)
}

var _ jqRunner = (*mockJQRunner)(nil)

// --- Mock File System Interfaces ---

// mockFileInfo implements fs.FileInfo for mockFileReader.Stat
type mockFileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	isDir   bool
	sys     interface{}
}

func (mfi *mockFileInfo) Name() string       { return mfi.name }
func (mfi *mockFileInfo) Size() int64        { return mfi.size }
func (mfi *mockFileInfo) Mode() fs.FileMode  { return mfi.mode }
func (mfi *mockFileInfo) ModTime() time.Time { return mfi.modTime }
func (mfi *mockFileInfo) IsDir() bool        { return mfi.isDir }
func (mfi *mockFileInfo) Sys() interface{}   { return mfi.sys }

// mockFileReader satisfies the FileReader interface without real files.
type mockFileReader struct {
	mock.Mock
	fileContent map[string][]byte    // Map filename to content
	fileInfo    map[string]fs.FileInfo // Map filename to FileInfo
}

// newMockFileReader creates a new mock file reader.
func newMockFileReader() *mockFileReader {
	return &mockFileReader{
		fileContent: make(map[string][]byte),
		fileInfo:    make(map[string]fs.FileInfo),
	}
}

// Open returns a reader for the mock content.
func (m *mockFileReader) Open(name string) (io.ReadCloser, error) {
	args := m.Called(name)
	err := args.Error(1) // Get potential error configured in mock setup
	if err != nil {
		return nil, err
	}
	// If no error configured, return the content
	content, found := m.fileContent[name]
	if !found {
		// If not specifically mocked with content, return a "not found" error like os.Open
		return nil, fs.ErrNotExist
	}
	// Return an io.NopCloser wrapping a bytes.Reader - this is readable multiple times
	return io.NopCloser(bytes.NewReader(content)), nil
}

// Stat returns mock file info.
func (m *mockFileReader) Stat(name string) (fs.FileInfo, error) {
	args := m.Called(name)
	err := args.Error(1) // Get potential error configured in mock setup
	if err != nil {
		return nil, err
	}
	info, found := m.fileInfo[name]
	if !found {
		// If not specifically mocked with info, return a "not found" error like os.Stat
		return nil, fs.ErrNotExist
	}
	return info, nil
}

var _ FileReader = (*mockFileReader)(nil)

// mockFileWriter satisfies the FileWriter interface, capturing WriteFile calls.
type mockFileWriter struct {
	mock.Mock
	// Map to store the data that was passed to WriteFile for verification.
	writtenFiles map[string][]byte
	// We still need OpenFile for the interface, but WriteFile tests won't use it.
	openedFiles map[string]*mockWriteCloser
}

// WriteFile captures the arguments for verification.
func (m *mockFileWriter) WriteFile(filename string, data []byte, perm fs.FileMode) error {
	args := m.Called(filename, data, perm)
	err := args.Error(0)
	if err == nil { // Only store if the mock call was configured to succeed
		if m.writtenFiles == nil {
			m.writtenFiles = make(map[string][]byte)
		}
		// Store a copy of the data to prevent modification after capture.
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)
		m.writtenFiles[filename] = dataCopy
	}
	return err
}

func (m *mockFileWriter) OpenFile(name string, flag int, perm fs.FileMode) (io.WriteCloser, error) {
	args := m.Called(name, flag, perm)
	err := args.Error(1)
	if err != nil {
		return nil, err
	}
	// If OpenFile is needed for future tests, implement mockWriteCloser logic here.
	// For now, primarily focused on WriteFile mocking.
	if m.openedFiles == nil {
		m.openedFiles = make(map[string]*mockWriteCloser)
	}
	mockWC := &mockWriteCloser{fileName: name}
	m.openedFiles[name] = mockWC
	return mockWC, nil
}

var _ FileWriter = (*mockFileWriter)(nil)

// mockWriteCloser remains for the OpenFile part of the interface, but less used now.
type mockWriteCloser struct {
	bytes.Buffer
	fileName string
	closeErr error
	wasClosed bool
}

func (m *mockWriteCloser) Close() error {
	m.wasClosed = true
	return m.closeErr
}

// --- Test Setup Helper ---
func setupTestRunner(t *testing.T, cfg *config.Config) (*Runner, *mockHTTPClientProvider, *mockRequestExecutor, *mockJQRunner, *mockFileWriter, *mockFileReader) {
	t.Helper()
	originalLogLevel := logging.GetLevel()
	logging.SetLevel(logging.Debug)
	t.Cleanup(func() { logging.SetLevel(originalLogLevel) })
	mockHTTP := new(mockHTTPClientProvider)
	// Use the enhanced mock executor
	mockExec := new(mockRequestExecutor)
	mockJQ := new(mockJQRunner)
	// Use the FileWriter mock that captures WriteFile calls
	mockWriter := new(mockFileWriter)
	mockReader := newMockFileReader()
	if cfg.Auth.Credentials == nil {
		cfg.Auth.Credentials = make(map[string]string)
	}
	if cfg.APIs == nil {
		cfg.APIs = make(map[string]config.APIConfig)
	}
	if cfg.Chain != nil {
		if cfg.Chain.Variables == nil {
			cfg.Chain.Variables = make(map[string]string)
		}
		if cfg.Chain.Steps == nil {
			cfg.Chain.Steps = []config.ChainStep{}
		}
	}
	opts := RunnerOpts{HttpClientProvider: mockHTTP, RequestExecutor: mockExec, JqRunner: mockJQ, FileWriter: mockWriter, FileReader: mockReader}
	runner := NewRunnerWithOpts(cfg, logging.GetLevel(), opts)
	// Return the concrete mock type for accessing captured values
	return runner, mockHTTP, mockExec, mockJQ, mockWriter, mockReader
}

// --- Helper Functions ---
func createTestAPIConfig(baseURL string, epPath string) map[string]config.APIConfig {
	return map[string]config.APIConfig{"testapi": {BaseURL: baseURL, AuthType: "none", Endpoints: map[string]config.EndpointConfig{"testep": {Path: epPath, Method: "POST"}, "getep": {Path: epPath, Method: "GET"}}}}
}
func createMockHttpResponse(statusCode int, headers http.Header, body string) *http.Response {
	if headers == nil {
		headers = http.Header{}
	}
	return &http.Response{StatusCode: statusCode, Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: &http.Request{Method: "GET", URL: &url.URL{Scheme: "http", Host: "dummy"}}}
}

// --- Tests ---

func TestRunner_Run_SimpleRequestStep_NoRegression(t *testing.T) {
	cfg := &config.Config{APIs: createTestAPIConfig("http://api.test", "/data"), Chain: &config.ChainConfig{Steps: []config.ChainStep{{Name: "fetch_data", Request: &config.ChainRequest{API: "testapi", Endpoint: "getep", Method: "GET", Data: `{"in": true}`}, Extract: map[string]string{"RESULT_BODY": "."}}}}, Retry: config.RetryConfig{MaxAttempts: 1}, Auth: config.AuthConfig{Default: "none"}, FipsMode: false}
	runner, mockHTTP, mockExec, mockJQ, _, _ := setupTestRunner(t, cfg)
	mockClient := &http.Client{}
	mockResp := createMockHttpResponse(200, http.Header{"Content-Type": {"application/json"}}, `{"id": 123}`)
	mockRespBodyBytes := []byte(`{"id": 123}`)
	apiConf := cfg.APIs["testapi"]
	mockHTTP.On("NewClient", &apiConf, &cfg.Auth, mock.Anything, cfg.FipsMode).Return(mockClient, nil).Once()
	// Simplified matcher - just check URL/Method. Body checked post-run.
	mockExec.On("ExecuteRequest", mockClient, mock.MatchedBy(func(r *http.Request) bool {
		return assert.Equal(t, "http://api.test/data", r.URL.String()) &&
			assert.Equal(t, "GET", r.Method)
	}), "none", cfg.Auth.Credentials, cfg.Retry, logging.GetLevel()).Return(mockResp, mockRespBodyBytes, nil).Once()
	mockJQ.On("RunFilter", mockRespBodyBytes, ".").Return(`{"id": 123}`, nil).Once()

	err := runner.Run(context.Background())

	require.NoError(t, err)
	mockHTTP.AssertExpectations(t)
	mockExec.AssertExpectations(t)
	mockJQ.AssertExpectations(t)
	assert.Equal(t, `{"id": 123}`, runner.state.vars["RESULT_BODY"])

	// Verify captured request body
	require.Len(t, mockExec.CapturedReqs, 1, "Expected 1 request to be captured")
	require.Len(t, mockExec.CapturedBodies, 1, "Expected 1 body to be captured")
	assert.Equal(t, `{"in": true}`, string(mockExec.CapturedBodies[0]), "Captured request body mismatch")
}

func TestRunner_Run_FileHandlingSteps(t *testing.T) {
	tmpDir := t.TempDir(); rawUploadFilePath := filepath.Join(tmpDir, "upload.bin"); multipartFilePath := filepath.Join(tmpDir, "data.txt"); downloadFilePath := filepath.Join(tmpDir, "downloaded_response.zip"); templateDownloadPath := filepath.Join(tmpDir, "download_{{.STEP_ID}}.out"); expectedRenderedDownloadPath := filepath.Join(tmpDir, "download_step1.out"); envVarDownloadPathTmpl := filepath.Join(tmpDir, "%DL_SUBDIR%/file.out"); t.Setenv("DL_SUBDIR", "results"); expectedEnvVarDownloadPath := filepath.Join(tmpDir, "results/file.out")
	// Use slightly different content to ensure correct source is verified
	rawUploadContent := "RAW BINARY UPLOAD DATA"; multipartFileContent := "Multipart file text content."; responseData := "DOWNLOAD RESPONSE DATA TO SAVE"; responseBytes := []byte(responseData)
	baseCfg := &config.Config{APIs: createTestAPIConfig("http://file.test", "/upload"), Retry: config.RetryConfig{MaxAttempts: 1}, Auth: config.AuthConfig{Default: "none"}, FipsMode: false, Chain: &config.ChainConfig{Variables: map[string]string{"STEP_ID": "step1"}}}

	testCases := []struct { name string; step config.ChainStep; setupMocks func(t *testing.T, mockHTTP *mockHTTPClientProvider, mockExec *mockRequestExecutor, mockReader *mockFileReader, mockWriter *mockFileWriter, mockJQ *mockJQRunner, cfg *config.Config); verify func(t *testing.T, runner *Runner, mockExec *mockRequestExecutor, mockWriter *mockFileWriter, err error); expectedErrMsg string }{
		{
			name: "Raw File Upload Success",
			step: config.ChainStep{Name: "raw_upload", Request: &config.ChainRequest{API: "testapi", Endpoint: "testep", Method: "PUT", UploadBodyFrom: rawUploadFilePath, Headers: map[string]string{"Content-Type": "application/custom-bin"}}},
			setupMocks: func(t *testing.T, mockHTTP *mockHTTPClientProvider, mockExec *mockRequestExecutor, mockReader *mockFileReader, mockWriter *mockFileWriter, mockJQ *mockJQRunner, cfg *config.Config) {
				mockClient := &http.Client{}; apiConf := cfg.APIs["testapi"]
				mockHTTP.On("NewClient", &apiConf, &cfg.Auth, mock.Anything, cfg.FipsMode).Return(mockClient, nil).Once()
				mockReader.fileContent[rawUploadFilePath] = []byte(rawUploadContent)
				mockReader.fileInfo[rawUploadFilePath] = &mockFileInfo{name: "upload.bin", size: int64(len(rawUploadContent))}
				// Expect Open twice: once for initial body, once for GetBody.
				mockReader.On("Open", rawUploadFilePath).Return(nil, nil).Times(2)
				mockReader.On("Stat", rawUploadFilePath).Return(nil, nil).Once()
				// Simplified matcher for ExecuteRequest
				mockExec.On("ExecuteRequest", mockClient, mock.MatchedBy(func(r *http.Request) bool {
					return r.Method == "PUT" && r.URL.String() == "http://file.test/upload"
				}), "none", mock.AnythingOfType("map[string]string"), cfg.Retry, mock.AnythingOfType("int")).Return(createMockHttpResponse(200, nil, "OK"), []byte("OK"), nil).Once()
			},
			verify: func(t *testing.T, runner *Runner, mockExec *mockRequestExecutor, mockWriter *mockFileWriter, err error) {
				require.NoError(t, err)
				// Verify captured request after run
				require.Len(t, mockExec.CapturedReqs, 1)
				require.Len(t, mockExec.CapturedBodies, 1)
				assert.Equal(t, rawUploadContent, string(mockExec.CapturedBodies[0]), "Captured body mismatch")
				assert.Equal(t, "application/custom-bin", mockExec.CapturedReqs[0].Header.Get("Content-Type"))
			},
		},
		{
			name: "Raw File Upload File Not Found",
			step: config.ChainStep{Name: "raw_upload_fail", Request: &config.ChainRequest{API: "testapi", Endpoint: "testep", UploadBodyFrom: "nonexistent.file"}},
			setupMocks: func(t *testing.T, mockHTTP *mockHTTPClientProvider, mockExec *mockRequestExecutor, mockReader *mockFileReader, mockWriter *mockFileWriter, mockJQ *mockJQRunner, cfg *config.Config) {
				openErr := fs.ErrNotExist // Use standard file system error
				mockReader.On("Open", "nonexistent.file").Return(nil, openErr).Once()
				// Stat will not be called if Open fails
			},
			verify: func(t *testing.T, runner *Runner, mockExec *mockRequestExecutor, mockWriter *mockFileWriter, err error) {
				require.Error(t, err)
				assert.ErrorIs(t, err, fs.ErrNotExist) // Check wrapped error type
				assert.Contains(t, err.Error(), "failed to open upload file 'nonexistent.file'", "Error message mismatch")
			},
			expectedErrMsg: "failed to open upload file", // Shorter snippet for main check
		},
		{
			name: "Multipart Upload Success",
			step: config.ChainStep{Name: "multipart_upload", Request: &config.ChainRequest{API: "testapi", Endpoint: "testep", FormData: map[string]string{"field1": "value1", "templateField": "{{.STEP_ID}}"}, FileFields: map[string]string{"file1": multipartFilePath, "meta": rawUploadFilePath}}},
			setupMocks: func(t *testing.T, mockHTTP *mockHTTPClientProvider, mockExec *mockRequestExecutor, mockReader *mockFileReader, mockWriter *mockFileWriter, mockJQ *mockJQRunner, cfg *config.Config) {
				mockClient := &http.Client{}; apiConf := cfg.APIs["testapi"]
				mockHTTP.On("NewClient", &apiConf, &cfg.Auth, mock.Anything, cfg.FipsMode).Return(mockClient, nil).Once()
				mockReader.fileContent[multipartFilePath] = []byte(multipartFileContent)
				mockReader.fileContent[rawUploadFilePath] = []byte(rawUploadContent)
				mockReader.On("Open", multipartFilePath).Return(nil, nil).Once()
				mockReader.On("Open", rawUploadFilePath).Return(nil, nil).Once()
				// Simplified matcher for ExecuteRequest
				mockExec.On("ExecuteRequest", mockClient, mock.MatchedBy(func(r *http.Request) bool {
					return r.Method == "POST" && r.URL.String() == "http://file.test/upload" && strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data")
				}), "none", mock.AnythingOfType("map[string]string"), cfg.Retry, mock.AnythingOfType("int")).Return(createMockHttpResponse(200, nil, "OK"), []byte("OK"), nil).Once()
			},
			verify: func(t *testing.T, runner *Runner, mockExec *mockRequestExecutor, mockWriter *mockFileWriter, err error) {
				require.NoError(t, err)
				// Verify captured multipart body after run
				require.Len(t, mockExec.CapturedReqs, 1)
				require.Len(t, mockExec.CapturedBodies, 1)
				capturedReq := mockExec.CapturedReqs[0]
				capturedBodyBytes := mockExec.CapturedBodies[0]
				require.NotNil(t, capturedBodyBytes)

				contentType := capturedReq.Header.Get("Content-Type")
				mediaType, params, err := mime.ParseMediaType(contentType)
				require.NoError(t, err)
				require.Equal(t, "multipart/form-data", mediaType)

				mr := multipart.NewReader(bytes.NewReader(capturedBodyBytes), params["boundary"])
				partsRead := 0; formFields := make(map[string]string); fileFields := make(map[string]string)
				for { part, err := mr.NextPart(); if errors.Is(err, io.EOF) { break }; require.NoError(t, err); partsRead++; partBytes, _ := io.ReadAll(part); if part.FileName() != "" { fileFields[part.FormName()] = string(partBytes) } else { formFields[part.FormName()] = string(partBytes) }	}
				// Verify multipart content read correctly
				assert.Equal(t, 4, partsRead, "Expected 4 parts (2 form, 2 file)"); assert.Equal(t, "value1", formFields["field1"]); assert.Equal(t, "step1", formFields["templateField"]); assert.Equal(t, multipartFileContent, fileFields["file1"]); assert.Equal(t, rawUploadContent, fileFields["meta"])
			},
		},
		// --- Download Tests ---
		{
			name: "Download Success",
			step: config.ChainStep{Name: "download_ok", Request: &config.ChainRequest{API: "testapi", Endpoint: "getep", Method: "GET", DownloadTo: downloadFilePath}},
			setupMocks: func(t *testing.T, mockHTTP *mockHTTPClientProvider, mockExec *mockRequestExecutor, mockReader *mockFileReader, mockWriter *mockFileWriter, mockJQ *mockJQRunner, cfg *config.Config) {
				mockClient := &http.Client{}; apiConf := cfg.APIs["testapi"]
				mockHTTP.On("NewClient", &apiConf, &cfg.Auth, mock.Anything, cfg.FipsMode).Return(mockClient, nil).Once()
				mockResp := createMockHttpResponse(200, nil, responseData)
				// Ensure ExecuteRequest mock returns the response body bytes correctly
				mockExec.On("ExecuteRequest", mockClient, mock.Anything, "none", mock.AnythingOfType("map[string]string"), cfg.Retry, mock.AnythingOfType("int")).Return(mockResp, responseBytes, nil).Once()
				// Expect WriteFile call
				mockWriter.On("WriteFile", downloadFilePath, responseBytes, fs.FileMode(0644)).Return(nil).Once()
			},
			verify: func(t *testing.T, runner *Runner, mockExec *mockRequestExecutor, mockWriter *mockFileWriter, err error) {
				require.NoError(t, err)
				// Verify WriteFile was called correctly
				mockWriter.AssertCalled(t, "WriteFile", downloadFilePath, responseBytes, fs.FileMode(0644))
				mockWriter.AssertExpectations(t)
				// Optionally check captured data if needed, though AssertCalled is primary
				// require.NotNil(t, mockWriter.writtenFiles)
				// writtenData, ok := mockWriter.writtenFiles[downloadFilePath]
				// require.True(t, ok, "File not found in writtenFiles map")
				// assert.Equal(t, responseData, string(writtenData), "Downloaded content mismatch")
			},
		},
		{
			name: "Download Success with Templated Path",
			step: config.ChainStep{Name: "download_template", Request: &config.ChainRequest{API: "testapi", Endpoint: "getep", Method: "GET", DownloadTo: templateDownloadPath}},
			setupMocks: func(t *testing.T, mockHTTP *mockHTTPClientProvider, mockExec *mockRequestExecutor, mockReader *mockFileReader, mockWriter *mockFileWriter, mockJQ *mockJQRunner, cfg *config.Config) {
				mockClient := &http.Client{}; apiConf := cfg.APIs["testapi"]
				mockHTTP.On("NewClient", &apiConf, &cfg.Auth, mock.Anything, cfg.FipsMode).Return(mockClient, nil).Once()
				mockResp := createMockHttpResponse(200, nil, responseData)
				mockExec.On("ExecuteRequest", mockClient, mock.Anything, "none", mock.AnythingOfType("map[string]string"), cfg.Retry, mock.AnythingOfType("int")).Return(mockResp, responseBytes, nil).Once()
				// Expect WriteFile call with the rendered path
				mockWriter.On("WriteFile", expectedRenderedDownloadPath, responseBytes, fs.FileMode(0644)).Return(nil).Once()
			},
			verify: func(t *testing.T, runner *Runner, mockExec *mockRequestExecutor, mockWriter *mockFileWriter, err error) {
				require.NoError(t, err)
				mockWriter.AssertCalled(t, "WriteFile", expectedRenderedDownloadPath, responseBytes, fs.FileMode(0644))
				mockWriter.AssertExpectations(t)
			},
		},
		{
			name: "Download Success with Env Var Path",
			step: config.ChainStep{Name: "download_env", Request: &config.ChainRequest{API: "testapi", Endpoint: "getep", Method: "GET", DownloadTo: envVarDownloadPathTmpl}},
			setupMocks: func(t *testing.T, mockHTTP *mockHTTPClientProvider, mockExec *mockRequestExecutor, mockReader *mockFileReader, mockWriter *mockFileWriter, mockJQ *mockJQRunner, cfg *config.Config) {
				mockClient := &http.Client{}; apiConf := cfg.APIs["testapi"]
				mockHTTP.On("NewClient", &apiConf, &cfg.Auth, mock.Anything, cfg.FipsMode).Return(mockClient, nil).Once()
				mockResp := createMockHttpResponse(200, nil, responseData)
				mockExec.On("ExecuteRequest", mockClient, mock.Anything, "none", mock.AnythingOfType("map[string]string"), cfg.Retry, mock.AnythingOfType("int")).Return(mockResp, responseBytes, nil).Once()
				// Expect WriteFile call with the rendered path
				mockWriter.On("WriteFile", expectedEnvVarDownloadPath, responseBytes, fs.FileMode(0644)).Return(nil).Once()
			},
			verify: func(t *testing.T, runner *Runner, mockExec *mockRequestExecutor, mockWriter *mockFileWriter, err error) {
				require.NoError(t, err)
				mockWriter.AssertCalled(t, "WriteFile", expectedEnvVarDownloadPath, responseBytes, fs.FileMode(0644))
				mockWriter.AssertExpectations(t)
			},
		},
		{
			name: "Download Fails During Write (WriteFile Error)",
			step: config.ChainStep{Name: "download_fail_write", Request: &config.ChainRequest{API: "testapi", Endpoint: "getep", Method: "GET", DownloadTo: downloadFilePath}},
			setupMocks: func(t *testing.T, mockHTTP *mockHTTPClientProvider, mockExec *mockRequestExecutor, mockReader *mockFileReader, mockWriter *mockFileWriter, mockJQ *mockJQRunner, cfg *config.Config) {
				mockClient := &http.Client{}; apiConf := cfg.APIs["testapi"]
				mockHTTP.On("NewClient", &apiConf, &cfg.Auth, mock.Anything, cfg.FipsMode).Return(mockClient, nil).Once()
				mockResp := createMockHttpResponse(200, nil, responseData)
				// Mock ExecuteRequest returns success
				mockExec.On("ExecuteRequest", mockClient, mock.Anything, "none", mock.AnythingOfType("map[string]string"), cfg.Retry, mock.AnythingOfType("int")).Return(mockResp, responseBytes, nil).Once()
				// Mock WriteFile to return an error
				writeErr := io.ErrShortWrite // Simulate a disk write error
				mockWriter.On("WriteFile", downloadFilePath, responseBytes, fs.FileMode(0644)).Return(writeErr).Once()
			},
			verify: func(t *testing.T, runner *Runner, mockExec *mockRequestExecutor, mockWriter *mockFileWriter, err error) {
				require.Error(t, err)
				// Check that the error from WriteFile is surfaced
				assert.ErrorIs(t, err, io.ErrShortWrite, "Expected io.ErrShortWrite from WriteFile")
				assert.Contains(t, err.Error(), "failed writing download file", "Error message mismatch")
				// Verify WriteFile was called
				mockWriter.AssertCalled(t, "WriteFile", downloadFilePath, responseBytes, fs.FileMode(0644))
				mockWriter.AssertExpectations(t)
			},
			expectedErrMsg: "failed writing download file",
		},
		{
			name: "Download with Header Extraction Only",
			step: config.ChainStep{Name: "download_extract_header", Request: &config.ChainRequest{API: "testapi", Endpoint: "getep", Method: "GET", DownloadTo: downloadFilePath}, Extract: map[string]string{"ETAG": `header:ETag:(.*)`}},
			setupMocks: func(t *testing.T, mockHTTP *mockHTTPClientProvider, mockExec *mockRequestExecutor, mockReader *mockFileReader, mockWriter *mockFileWriter, mockJQ *mockJQRunner, cfg *config.Config) {
				mockClient := &http.Client{}; apiConf := cfg.APIs["testapi"]
				mockHTTP.On("NewClient", &apiConf, &cfg.Auth, mock.Anything, cfg.FipsMode).Return(mockClient, nil).Once()
				mockHeaders := http.Header{"Etag": {`"abc-123"`}};
				mockResp := createMockHttpResponse(200, mockHeaders, responseData)
				mockExec.On("ExecuteRequest", mockClient, mock.Anything, "none", mock.AnythingOfType("map[string]string"), cfg.Retry, mock.AnythingOfType("int")).Return(mockResp, responseBytes, nil).Once()
				// Expect WriteFile call
				mockWriter.On("WriteFile", downloadFilePath, responseBytes, fs.FileMode(0644)).Return(nil).Once()
			},
			verify: func(t *testing.T, runner *Runner, mockExec *mockRequestExecutor, mockWriter *mockFileWriter, err error) {
				require.NoError(t, err)
				// Verify WriteFile was called
				mockWriter.AssertCalled(t, "WriteFile", downloadFilePath, responseBytes, fs.FileMode(0644))
				// Verify extraction happened
				etag, found := runner.state.Get("ETAG")
				assert.True(t, found, "ETAG should have been extracted")
				assert.Equal(t, `"abc-123"`, etag) // Regex (.*) captures the quoted string
				jqMock, _ := runner.jqRunner.(*mockJQRunner)
				jqMock.AssertNotCalled(t, "RunFilter", mock.Anything, mock.Anything) // Ensure JQ wasn't called
			},
		},
	} // End testCases

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			currentCfg := *baseCfg; currentCfg.Chain = &config.ChainConfig{Variables: make(map[string]string), Steps: []config.ChainStep{tc.step}}; for k, v := range baseCfg.Chain.Variables { currentCfg.Chain.Variables[k] = v }
			runner, mockHTTP, mockExec, mockJQ, mockWriter, mockReader := setupTestRunner(t, &currentCfg)
			cfg := runner.cfg // Get reference to config used by runner for mocks
			if tc.setupMocks != nil { tc.setupMocks(t, mockHTTP, mockExec, mockReader, mockWriter, mockJQ, cfg) } // Pass cfg
			err := runner.Run(context.Background())
			// Use the mock executor passed to the verify function
			if tc.verify != nil { tc.verify(t, runner, mockExec, mockWriter, err)
			} else if tc.expectedErrMsg != "" { require.Error(t, err); assert.Contains(t, err.Error(), tc.expectedErrMsg)
			} else { require.NoError(t, err) }
			mockHTTP.AssertExpectations(t); mockExec.AssertExpectations(t); mockReader.AssertExpectations(t); mockWriter.AssertExpectations(t); mockJQ.AssertExpectations(t) // Add JQ check
		})
	}
}

// --- Helper for testing read failures ---
// errorReader simulates an io.ReadCloser that returns an error during Read.
type errorReader struct {
	readErr error // The error to return
}

// Read returns the configured error immediately.
func (r *errorReader) Read(p []byte) (n int, err error) {
	if r.readErr == nil {
		return 0, io.EOF // Default to EOF if no specific error set
	}
	return 0, r.readErr
}

// Close is a no-op.
func (r *errorReader) Close() error { return nil }

// Ensure errorReader implements io.ReadCloser.
var _ io.ReadCloser = (*errorReader)(nil)