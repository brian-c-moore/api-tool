package jq

import (
	// "bytes" // No longer needed
	"errors"
	"io"
	// "os/exec" // No longer needed for direct mocking here
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock Command Runner ---
// mockCommandRunner satisfies the CommandRunner interface for testing.
type mockCommandRunner struct {
	// Mock control fields
	RunShouldError bool   // Whether the mock Run() should return an error
	RunError       error  // The specific error Run() should return
	StdoutContent  string // Content mock Run() writes to Stdout
	StderrContent  string // Content mock Run() writes to Stderr

	// Fields to capture assigned values (optional verification)
	capturedStdin  io.Reader
	capturedStdout io.Writer
	capturedStderr io.Writer
}

// Implement CommandRunner interface methods

func (m *mockCommandRunner) SetStdin(r io.Reader) {
	m.capturedStdin = r
}

func (m *mockCommandRunner) SetStdout(w io.Writer) {
	m.capturedStdout = w
}

func (m *mockCommandRunner) SetStderr(w io.Writer) {
	m.capturedStderr = w
}

// Run is the mocked execution method.
func (m *mockCommandRunner) Run() error {
	// Simulate writing stdout content if a writer was captured
	if m.capturedStdout != nil && m.StdoutContent != "" {
		_, _ = io.WriteString(m.capturedStdout, m.StdoutContent)
	}
	// Simulate writing stderr content if a writer was captured
	if m.capturedStderr != nil && m.StderrContent != "" {
		_, _ = io.WriteString(m.capturedStderr, m.StderrContent)
	}
	// Simulate consuming stdin (optional, but good practice)
	if m.capturedStdin != nil {
		_, _ = io.Copy(io.Discard, m.capturedStdin)
	}

	if m.RunShouldError {
		if m.RunError == nil {
			return errors.New("mock cmd.Run() failed")
		}
		return m.RunError
	}
	return nil // Success
}

// --- Test Setup ---

// setupJqMocks replaces the package-level functions/factories in the jq package
func setupJqMocks(t *testing.T, lookPathErr error, cmdRunnerToReturn *mockCommandRunner) func() {
	t.Helper()

	// Mock ExecLookPath using the exported variable and SetLookPath helper
	restoreLookPath := SetLookPath(func(file string) (string, error) {
		require.Equal(t, "jq", file, "Expected LookPath for 'jq'")
		if lookPathErr != nil {
			return "", lookPathErr
		}
		return "/fake/jq", nil
	})

	// Mock the CommandFactory using the exported helper
	restoreFactory := SetCommandFactory(func(name string, arg ...string) CommandRunner {
		// Return the pre-configured mockCommandRunner instance for this test case
		// If LookPath failed, cmdRunnerToReturn might be nil, which is fine,
		// as the factory shouldn't be called in that case.
		require.NotNil(t, cmdRunnerToReturn, "CommandFactory called unexpectedly when LookPath should have failed")
		return cmdRunnerToReturn
	})

	// Return a single teardown function
	return func() {
		restoreLookPath()
		restoreFactory()
	}
}

// --- Tests ---

func TestRunFilter(t *testing.T) {

	validInput := []byte(`{"name": "test", "value": 123, "items": [1, 2]}`)
	invalidInput := []byte(`{"name": "test",`) // Malformed JSON
	jqNotFoundErr := errors.New("jq not found in PATH")
	jqExecErr := errors.New("exit status 1") // Generic exec error

	testCases := []struct {
		name           string
		input          []byte
		filter         string
		lookPathErr    error              // Error for ExecLookPath mock
		mockRunner     *mockCommandRunner // Mock runner to inject
		expectedOutput string
		expectError    bool
		errorContains  string
	}{
		{
			name:   "Valid Filter and Input",
			input:  validInput,
			filter: ".name",
			mockRunner: &mockCommandRunner{ // Simulate successful run
				StdoutContent: `"test"` + "\n",
			},
			expectedOutput: `"test"`,
			expectError:    false,
		},
		{
			name:   "Valid Filter - Raw Output Number",
			input:  validInput,
			filter: ".value",
			mockRunner: &mockCommandRunner{
				StdoutContent: "123\n",
			},
			expectedOutput: "123",
			expectError:    false,
		},
		{
			name:   "Valid Filter - Complex Output JSON",
			input:  validInput,
			filter: "{newName: .name, firstItem: .items[0]}",
			mockRunner: &mockCommandRunner{
				StdoutContent: `{"newName":"test","firstItem":1}` + "\n",
			},
			expectedOutput: `{"newName":"test","firstItem":1}`,
			expectError:    false,
		},
		{
			name:        "JQ Not Found",
			input:       validInput,
			filter:      ".",
			lookPathErr: jqNotFoundErr, // Simulate LookPath failure
			mockRunner:  nil,           // Factory shouldn't be called
			expectError: true,
			errorContains: "failed to find 'jq' executable",
		},
		{
			name:   "JQ Execution Error (bad filter)",
			input:  validInput,
			filter: ".invalid++",
			mockRunner: &mockCommandRunner{
				RunShouldError: true,
				RunError:       jqExecErr,
				StderrContent:  "jq: error: syntax error, unexpected INVALID_CHARACTER\n",
			},
			expectError:   true,
			errorContains: "jq command execution failed",
		},
		{
			name:   "JQ Error on Invalid Input JSON",
			input:  invalidInput,
			filter: ".",
			mockRunner: &mockCommandRunner{
				RunShouldError: true,
				RunError:       jqExecErr,
				StderrContent:  "parse error: Invalid numeric literal at line 1, column 15\n",
			},
			expectError:   true,
			errorContains: "jq command execution failed",
		},
		{
			name:   "Empty Input",
			input:  []byte(""),
			filter: ".",
			mockRunner: &mockCommandRunner{
				RunShouldError: true,
				RunError:       jqExecErr,
				StderrContent:  "jq: error: Cannot iterate over null (null)\n",
			},
			expectError:   true,
			errorContains: "jq command execution failed",
		},
		{
			name:   "Empty Filter",
			input:  validInput,
			filter: "",
			mockRunner: &mockCommandRunner{
				RunShouldError: true,
				RunError:       jqExecErr,
				StderrContent:  "jq: error: The filter script must be a string\n",
			},
			expectError:   true,
			errorContains: "jq command execution failed",
		},
		{
			name:   "Successful run with stderr warning",
			input:  validInput,
			filter: ".name",
			mockRunner: &mockCommandRunner{
				StdoutContent:  `"test"` + "\n",
				StderrContent:  "warning: something minor happened\n",
				RunShouldError: false, // Run succeeds
			},
			expectedOutput: `"test"`,
			expectError:    false, // Success despite stderr
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mocks using the interface approach
			teardown := setupJqMocks(t, tc.lookPathErr, tc.mockRunner)
			defer teardown()

			actualOutput, err := RunFilter(tc.input, tc.filter)

			if tc.expectError {
				require.Error(t, err, "Expected an error but got nil")
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains, "Error message mismatch")
				}
				// Check if stderr was included in the error message when Run failed
				if tc.mockRunner != nil && tc.mockRunner.RunShouldError && tc.mockRunner.StderrContent != "" {
					trimmedStderr := strings.TrimSpace(tc.mockRunner.StderrContent)
					if trimmedStderr != "" {
						assert.Contains(t, err.Error(), trimmedStderr, "Expected stderr content ('%s') in error message", trimmedStderr)
					}
				}
			} else {
				require.NoError(t, err, "Did not expect an error but got: %v", err)
				assert.Equal(t, strings.TrimSpace(tc.expectedOutput), actualOutput, "Output mismatch")
			}
		})
	}
}
