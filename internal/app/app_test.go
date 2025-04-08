package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"api-tool/internal/config"
	"api-tool/internal/logging"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// --- Mocks ---

type mockConfigLoader struct {
	mock.Mock
}

func (m *mockConfigLoader) Load(filename string) (*config.Config, error) {
	args := m.Called(filename)
	cfg, _ := args.Get(0).(*config.Config)
	return cfg, args.Error(1)
}

type mockChainRunner struct {
	mock.Mock
}

func (m *mockChainRunner) Run(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

type mockChainRunnerFactory struct {
	mock.Mock
}

func (m *mockChainRunnerFactory) New(cfg *config.Config, logLevel int) chainRunner {
	args := m.Called(cfg, logLevel)
	runner, _ := args.Get(0).(chainRunner)
	return runner
}

type mockExecutor struct {
	mock.Mock
	CapturedReq *http.Request
}

func (m *mockExecutor) ExecuteRequest(client *http.Client, req *http.Request, effAuth string, creds map[string]string, retry config.RetryConfig, lvl int) (*http.Response, []byte, error) {
	m.CapturedReq = req
	args := m.Called(client, req, effAuth, creds, retry, lvl)
	resp, _ := args.Get(0).(*http.Response)
	respBody, _ := args.Get(1).([]byte)
	err := args.Error(2)
	if resp != nil && resp.Body == nil && respBody != nil {
		resp.Body = io.NopCloser(bytes.NewReader(respBody))
	}
	return resp, respBody, err
}

func (m *mockExecutor) HandlePagination(client *http.Client, req *http.Request, epCfg config.EndpointConfig, resp *http.Response, body []byte, effAuth string, creds map[string]string, retry config.RetryConfig, lvl int) (string, error) {
	args := m.Called(client, req, epCfg, resp, body, effAuth, creds, retry, lvl)
	return args.String(0), args.Error(1)
}

var _ requestExecutor = (*mockExecutor)(nil)

func newMockResponse(statusCode int, body string) *http.Response {
	return &http.Response{StatusCode: statusCode, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}
}

func createTempYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test_config.yaml")
	err := os.WriteFile(path, []byte(content), 0644)
	require.NoError(t, err)
	return path
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	originalStderr := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	defer func() {
		os.Stderr = originalStderr
	}()

	fn()

	err = w.Close()
	require.NoError(t, err)

	var buf bytes.Buffer
	_, err = buf.ReadFrom(r)
	require.NoError(t, err)
	err = r.Close()
	require.NoError(t, err)

	return buf.String()
}

// --- Tests ---

func TestAppRunner_Run_Help(t *testing.T) {
	runner := NewAppRunner()

	testCases := []struct {
		name string
		args []string
	}{
		{"Help Flag Long", []string{"--help"}},
		{"Help Flag Short", []string{"-help"}},
		{"No Args", []string{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			stderrOutput := captureStderr(t, func() {
				err := runner.Run(tc.args)
				assert.NoError(t, err, "Running with help/no args should not produce an error")
			})
			assert.Contains(t, stderrOutput, "Usage:", "Stderr should contain usage instructions")
			assert.Contains(t, stderrOutput, "-config string", "Stderr should contain usage instructions")
		})
	}
}

func TestAppRunner_Run_FlagErrors(t *testing.T) {
	runner := NewAppRunner()

	testCases := []struct {
		name          string
		args          []string
		expectedError error
	}{
		{"Invalid Flag", []string{"--invalid-flag"}, ErrUsage},
		{"Flag Needs Argument", []string{"-config"}, ErrUsage},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := runner.Run(tc.args)
			require.Error(t, err, "Expected an error for invalid flags")
			assert.ErrorIs(t, err, tc.expectedError, "Expected specific usage error")
		})
	}
}

func TestAppRunner_Run_ConfigErrors(t *testing.T) {
	mockLoader := new(mockConfigLoader)
	runner := NewAppRunnerWithOpts(AppRunnerOpts{
		ConfigLoader: mockLoader,
	})

	t.Run("Config Not Found", func(t *testing.T) {
		err := runner.Run([]string{"-config", "nonexistent.yaml", "-api", "a", "-endpoint", "e"})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConfigNotFound)
		mockLoader.AssertNotCalled(t, "Load", mock.Anything)
	})

	t.Run("Config Load Error", func(t *testing.T) {
		dummyFile := createTempYAML(t, "invalid yaml:")
		loadErr := errors.New("mock yaml parse error")
		mockLoader.On("Load", dummyFile).Return(nil, loadErr).Once()

		err := runner.Run([]string{"-config", dummyFile, "-api", "a", "-endpoint", "e"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), loadErr.Error())
		mockLoader.AssertExpectations(t)
	})
}

func TestAppRunner_Run_ModeDispatch(t *testing.T) {
	mockLoader := new(mockConfigLoader)
	mockChainFactory := new(mockChainRunnerFactory)
	mockExecutor := new(mockExecutor)
	mockCRunner := new(mockChainRunner)

	runner := NewAppRunnerWithOpts(AppRunnerOpts{
		ConfigLoader:       mockLoader,
		ChainRunnerFactory: mockChainFactory,
		RequestExecutor:    mockExecutor,
	})

	validBaseConfig := &config.Config{
		APIs: map[string]config.APIConfig{
			"testapi": {
				BaseURL:  "http://test.com/",
				AuthType: "none",
				Endpoints: map[string]config.EndpointConfig{
					"ep1": {Path: "path"},
					"pageEp": {Path: "page-path", Pagination: &config.PaginationConfig{Type: "page", Limit: 10, PageParam: "p", SizeParam: "s", LimitParam: "s"}},
				},
			},
			"dummy": {
				BaseURL:  "http://dummy.com/",
				AuthType: "none",
				Endpoints: map[string]config.EndpointConfig{
					"ep1": {Path: "/p"},
				},
			},
		},
		Retry:   config.RetryConfig{MaxAttempts: 1, Backoff: 1},
		Logging: config.LoggingConfig{Level: "info"},
		Auth:    config.AuthConfig{Default: "none"},
	}
	validChainConfig := *validBaseConfig
	validChainConfig.Chain = &config.ChainConfig{Steps: []config.ChainStep{{Name: "dummy", Request: &config.ChainRequest{API: "dummy", Endpoint: "ep1"}}}}

	dummyConfigFile := createTempYAML(t, `
apis:
  dummy:
    base_url: http://dummy.com/
    auth_type: none
    endpoints:
      ep1: {path: /p}
  testapi:
    base_url: http://test.com/
    auth_type: none
    endpoints:
      ep1: {path: path}
      pageEp: {path: page-path, pagination: {type: page, limit: 10, page_param: p, size_param: s, limit_param: s}}
`)

	testCases := []struct {
		name              string
		args              []string
		mockConfig        *config.Config
		setupMocks        func()
		expectError       bool
		expectStdout      string
		expectErrorIs     error
		expectErrContains string
	}{
		{
			name:          "Single Mode - Missing API",
			args:          []string{"-config", dummyConfigFile, "-endpoint", "ep1"},
			mockConfig:    validBaseConfig,
			setupMocks: func() {
				mockLoader.On("Load", dummyConfigFile).Return(validBaseConfig, nil).Once()
			},
			expectError:   true,
			expectErrorIs: ErrMissingArgs,
		},
		{
			name:          "Single Mode - Missing Endpoint",
			args:          []string{"-config", dummyConfigFile, "-api", "testapi"},
			mockConfig:    validBaseConfig,
			setupMocks: func() {
				mockLoader.On("Load", dummyConfigFile).Return(validBaseConfig, nil).Once()
			},
			expectError:   true,
			expectErrorIs: ErrMissingArgs,
		},
		{
			name:       "Single Mode - Success",
			args:       []string{"-config", dummyConfigFile, "-api", "testapi", "-endpoint", "ep1", "-method", "POST", "-data", `{"ok":true}`},
			mockConfig: validBaseConfig,
			setupMocks: func() {
				mockLoader.On("Load", dummyConfigFile).Return(validBaseConfig, nil).Once()
				mockExecutor.On("ExecuteRequest", mock.Anything, mock.MatchedBy(func(r *http.Request) bool {
					assert.Equal(t, "POST", r.Method)
					assert.Equal(t, "http://test.com/path", r.URL.String())
					bodyBytes, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					assert.JSONEq(t, `{"ok":true}`, string(bodyBytes))
					return true
				}), "none", mock.Anything, mock.Anything, mock.Anything).Return(
					newMockResponse(200, `{"result":"success"}`), []byte(`{"result":"success"}`), nil,
				).Once()
				mockExecutor.On("HandlePagination", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, "none", mock.Anything, mock.Anything, mock.Anything).Return(`{"result":"success"}`, nil).Maybe()
			},
			expectError:  false,
			expectStdout: `{"result":"success"}`,
		},
		{
			name:       "Single Mode - Execution Fails (DNS)", // Fixed test
			args:       []string{"-config", dummyConfigFile, "-api", "testapi", "-endpoint", "ep1"},
			mockConfig: validBaseConfig,
			setupMocks: func() {
				mockLoader.On("Load", dummyConfigFile).Return(validBaseConfig, nil).Once()
				// Mock ExecuteRequest to return the expected network error
				expectedNetworkError := fmt.Errorf("request execution failed: Get \"http://test.com/path\": dial tcp: lookup test.com: no such host")
				mockExecutor.On("ExecuteRequest",
					mock.Anything, // client
					mock.MatchedBy(func(r *http.Request) bool {
						return r.URL.String() == "http://test.com/path"
					}), // request
					"none",        // effectiveAuthType
					mock.Anything, // creds
					mock.Anything, // retryCfg
					mock.Anything, // logLevel
				).Return(nil, nil, expectedNetworkError).Once()
			},
			expectError:       true,
			expectErrContains: "dial tcp: lookup test.com: no such host",
		},
		{
			name:       "Chain Mode - Success Path",
			args:       []string{"-config", dummyConfigFile, "-chain"},
			mockConfig: &validChainConfig,
			setupMocks: func() {
				mockLoader.On("Load", dummyConfigFile).Return(&validChainConfig, nil).Once()
				mockChainFactory.On("New", &validChainConfig, logging.Info).Return(mockCRunner).Once()
				mockCRunner.On("Run", mock.AnythingOfTypeArgument("context.backgroundCtx")).Return(nil).Once()
			},
			expectError: false,
		},
		{
			name:       "Chain Mode - Runner Fails",
			args:       []string{"-config", dummyConfigFile, "-chain"},
			mockConfig: &validChainConfig,
			setupMocks: func() {
				chainErr := errors.New("chain failed")
				mockLoader.On("Load", dummyConfigFile).Return(&validChainConfig, nil).Once()
				mockChainFactory.On("New", &validChainConfig, logging.Info).Return(mockCRunner).Once()
				mockCRunner.On("Run", mock.AnythingOfTypeArgument("context.backgroundCtx")).Return(chainErr).Once()
			},
			expectError:       true,
			expectErrContains: "chain failed",
		},
		{
			name:       "Chain Mode - Config Missing Chain Section",
			args:       []string{"-config", dummyConfigFile, "-chain"},
			mockConfig: validBaseConfig,
			setupMocks: func() {
				mockLoader.On("Load", dummyConfigFile).Return(validBaseConfig, nil).Once()
			},
			expectError:       true,
			expectErrContains: "no 'chain' section found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockLoader.Mock.ExpectedCalls = nil
			mockChainFactory.Mock.ExpectedCalls = nil
			mockCRunner.Mock.ExpectedCalls = nil
			mockExecutor.Mock.ExpectedCalls = nil
			mockLoader.Mock.Calls = nil
			mockExecutor.Mock.Calls = nil
			mockChainFactory.Mock.Calls = nil
			mockCRunner.Mock.Calls = nil
			mockExecutor.CapturedReq = nil

			tc.setupMocks()

			err := runner.Run(tc.args)

			if tc.expectStdout != "" {
				// Stdout capture would be needed here for full verification
			}
			if tc.expectError {
				require.Error(t, err, "Expected an error for test case: %s", tc.name)
				if tc.expectErrorIs != nil {
					assert.ErrorIs(t, err, tc.expectErrorIs, "Expected specific error type for test case: %s", tc.name)
				}
				if tc.expectErrContains != "" {
					assert.Contains(t, err.Error(), tc.expectErrContains, "Expected error message to contain '%s' for test case: %s", tc.expectErrContains, tc.name)
				}
			} else {
				assert.NoError(t, err, "Did not expect an error for test case: %s", tc.name)
			}

			mockLoader.AssertExpectations(t)
			mockChainFactory.AssertExpectations(t)
			mockExecutor.AssertExpectations(t)
			mockCRunner.AssertExpectations(t)
		})
	}
}

func TestAppRunner_Run_Single_InitialPaginationParams(t *testing.T) {
	mockLoader := new(mockConfigLoader)
	mockExecutor := new(mockExecutor)
	runner := NewAppRunnerWithOpts(AppRunnerOpts{
		ConfigLoader:       mockLoader,
		ChainRunnerFactory: new(defaultChainRunnerFactory),
		RequestExecutor:    mockExecutor,
	})

	cfgContent := `
apis:
  testapi:
    base_url: http://test.com/
    auth_type: none
    endpoints:
      force_offset:
        path: offset
        pagination:
          type: offset
          limit: 5
          offset_param: offset
          limit_param: limit
          force_initial_pagination_params: true
      no_force_page:
        path: page
        pagination:
          type: page
          limit: 10
          start_page: 1
          page_param: page
          size_param: size
          limit_param: size
          # force_initial_pagination_params defaults to false
`
	cfgPath := createTempYAML(t, cfgContent)
	loadedCfg, loadErr := config.LoadConfig(cfgPath)
	require.NoError(t, loadErr)

	// --- Test Case 1: Force initial offset params ---
	mockLoader.On("Load", cfgPath).Return(loadedCfg, nil).Once()
	mockExecutor.On("ExecuteRequest", mock.Anything, mock.Anything, "none", mock.Anything, mock.Anything, mock.Anything).Return(newMockResponse(200, `[]`), []byte(`[]`), nil).Once()
	mockExecutor.On("HandlePagination", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, "none", mock.Anything, mock.Anything, mock.Anything).Return(`[]`, nil).Once()

	err := runner.Run([]string{"-config", cfgPath, "-api", "testapi", "-endpoint", "force_offset"})
	require.NoError(t, err)
	require.NotNil(t, mockExecutor.CapturedReq)
	assert.Contains(t, mockExecutor.CapturedReq.URL.RawQuery, "limit=5")
	assert.Contains(t, mockExecutor.CapturedReq.URL.RawQuery, "offset=0")
	mockLoader.AssertExpectations(t)
	mockExecutor.AssertExpectations(t)

	// --- Test Case 2: Do NOT force initial page params (default) ---
	mockLoader.Mock.ExpectedCalls = nil
	mockExecutor.Mock.Calls = nil
	mockExecutor.Mock.ExpectedCalls = nil
	mockExecutor.CapturedReq = nil
	mockLoader.On("Load", cfgPath).Return(loadedCfg, nil).Once()
	mockExecutor.On("ExecuteRequest", mock.Anything, mock.Anything, "none", mock.Anything, mock.Anything, mock.Anything).Return(newMockResponse(200, `[]`), []byte(`[]`), nil).Once()
	mockExecutor.On("HandlePagination", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, "none", mock.Anything, mock.Anything, mock.Anything).Return(`[]`, nil).Once()

	err = runner.Run([]string{"-config", cfgPath, "-api", "testapi", "-endpoint", "no_force_page"})
	require.NoError(t, err)
	require.NotNil(t, mockExecutor.CapturedReq)
	assert.NotContains(t, mockExecutor.CapturedReq.URL.RawQuery, "page=1")
	assert.NotContains(t, mockExecutor.CapturedReq.URL.RawQuery, "size=10")
	mockLoader.AssertExpectations(t)
	mockExecutor.AssertExpectations(t)
}