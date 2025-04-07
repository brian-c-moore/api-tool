package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"api-tool/internal/config"
	"api-tool/internal/logging"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// --- Mocks ---

// mockConfigLoader allows controlling config loading results.
type mockConfigLoader struct {
	mock.Mock
}

func (m *mockConfigLoader) Load(filename string) (*config.Config, error) {
	args := m.Called(filename)
	cfg, _ := args.Get(0).(*config.Config)
	return cfg, args.Error(1)
}

// mockChainRunner allows asserting that Run was called.
type mockChainRunner struct {
	mock.Mock
}

func (m *mockChainRunner) Run(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// mockChainRunnerFactory returns the mockChainRunner.
type mockChainRunnerFactory struct {
	mock.Mock
}

func (m *mockChainRunnerFactory) New(cfg *config.Config, logLevel int) chainRunner {
	args := m.Called(cfg, logLevel)
	runner, _ := args.Get(0).(chainRunner) // Get the configured mock runner
	return runner
}

// Helper to create a temporary config file
func createTempYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test_config.yaml")
	err := os.WriteFile(path, []byte(content), 0644)
	require.NoError(t, err)
	return path
}

// Helper function to capture stderr
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	originalStderr := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	defer func() {
		os.Stderr = originalStderr // Restore original stderr
	}()

	fn() // Execute the function that might write to stderr

	err = w.Close() // Close the writer to signal EOF to the reader
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
		// Use Contains because the actual error includes file path
		assert.Contains(t, err.Error(), loadErr.Error())
		mockLoader.AssertExpectations(t)
	})
}

func TestAppRunner_Run_ModeDispatch(t *testing.T) {
	mockLoader := new(mockConfigLoader)
	mockChainFactory := new(mockChainRunnerFactory)
	mockCRunner := new(mockChainRunner)

	runner := NewAppRunnerWithOpts(AppRunnerOpts{
		ConfigLoader:       mockLoader,
		ChainRunnerFactory: mockChainFactory,
	})

	validBaseConfig := &config.Config{
		APIs: map[string]config.APIConfig{
			"testapi": {
				BaseURL:  "http://test.com", // Keep non-resolvable host
				AuthType: "none",
				Endpoints: map[string]config.EndpointConfig{
					"ep1": {Path: "/path"},
				},
			},
		},
		Retry:   config.RetryConfig{MaxAttempts: 1, Backoff: 1},
		Logging: config.LoggingConfig{Level: "info"},
		Auth:    config.AuthConfig{},
	}
	validChainConfig := *validBaseConfig
	validChainConfig.Chain = &config.ChainConfig{Steps: []config.ChainStep{{Name: "dummy"}}}

	// Use raw string literal for multiline content
	dummyConfigFile := createTempYAML(t, `apis:
 dummy: {}`)

	testCases := []struct {
		name             string
		args             []string
		mockConfig       *config.Config
		setupMocks       func()
		expectError      bool // Changed from expectedError
		expectErrorIs    error // For checking specific error types like ErrMissingArgs
		expectErrContains string // Use this for errors where we check substrings
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
			name:       "Single Mode - Execution Fails (Network Attempt)", // Renamed test
			args:       []string{"-config", dummyConfigFile, "-api", "testapi", "-endpoint", "ep1"},
			mockConfig: validBaseConfig,
			setupMocks: func() {
				mockLoader.On("Load", dummyConfigFile).Return(validBaseConfig, nil).Once()
				// No mocks for httpclient/executor needed here - allow real attempt
			},
			expectError: true, // Just expect *an* error from the network attempt
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
			expectErrContains: "chain failed", // Check the specific error message from the mock
		},
		{
			name:       "Chain Mode - Config Missing Chain Section",
			args:       []string{"-config", dummyConfigFile, "-chain"},
			mockConfig: validBaseConfig, // Use config without chain
			setupMocks: func() {
				mockLoader.On("Load", dummyConfigFile).Return(validBaseConfig, nil).Once()
			},
			expectError:       true,
			expectErrContains: "no 'chain' section found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset mocks for each test case
			mockLoader.Mock.ExpectedCalls = nil
			mockChainFactory.Mock.ExpectedCalls = nil
			mockCRunner.Mock.ExpectedCalls = nil
			mockLoader.Mock.Calls = nil
			mockChainFactory.Mock.Calls = nil
			mockCRunner.Mock.Calls = nil

			tc.setupMocks()

			err := runner.Run(tc.args)

			if tc.expectError {
				require.Error(t, err, "Expected an error for test case: %s", tc.name)
				if tc.expectErrorIs != nil {
					assert.ErrorIs(t, err, tc.expectErrorIs, "Expected specific error type for test case: %s", tc.name)
				}
				if tc.expectErrContains != "" {
                        // Use assert.Contains for checking substrings in the error message
					assert.Contains(t, err.Error(), tc.expectErrContains, "Expected error message to contain '%s' for test case: %s", tc.expectErrContains, tc.name)
				}
			} else {
				assert.NoError(t, err, "Did not expect an error for test case: %s", tc.name)
			}

			mockLoader.AssertExpectations(t)
			mockChainFactory.AssertExpectations(t)
			mockCRunner.AssertExpectations(t)
		})
	}
}
