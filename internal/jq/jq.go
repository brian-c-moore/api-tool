package jq

import (
	"bytes"
	"fmt"
	"io" // Needed for interface fields
	"os/exec"
	"strings"

	"api-tool/internal/logging"
)

// --- Interface for Command Execution ---

// CommandRunner defines the interface for running an external command.
// This matches the methods and fields of exec.Cmd that RunFilter uses.
type CommandRunner interface {
	Run() error
	SetStdin(r io.Reader)
	SetStdout(w io.Writer)
	SetStderr(w io.Writer)
}

// commandRunnerAdapter wraps *exec.Cmd to satisfy CommandRunner.
type commandRunnerAdapter struct {
	cmd *exec.Cmd
}

func (c *commandRunnerAdapter) Run() error {
	return c.cmd.Run()
}

func (c *commandRunnerAdapter) SetStdin(r io.Reader) {
	c.cmd.Stdin = r
}

func (c *commandRunnerAdapter) SetStdout(w io.Writer) {
	c.cmd.Stdout = w
}

func (c *commandRunnerAdapter) SetStderr(w io.Writer) {
	c.cmd.Stderr = w
}

// CommandFactory defines the function signature for creating a CommandRunner.
// This allows injecting different implementations (real or mock).
type CommandFactory func(name string, arg ...string) CommandRunner

// --- Variables for Mocking / Default Implementation ---
var (
	// ExecLookPath remains injectable for finding the command.
	ExecLookPath = exec.LookPath

	// DefaultCommandFactory provides the real implementation using exec.Command.
	DefaultCommandFactory CommandFactory = func(name string, arg ...string) CommandRunner {
		return &commandRunnerAdapter{cmd: exec.Command(name, arg...)}
	}

	// commandFactory holds the currently active factory (real or mock).
	// It defaults to the real one but can be replaced by tests.
	commandFactory = DefaultCommandFactory
)

// SetCommandFactory allows tests to inject a mock factory.
// IMPORTANT: Call the returned function in test teardown to restore.
func SetCommandFactory(factory CommandFactory) (restore func()) {
	current := commandFactory
	commandFactory = factory
	return func() { commandFactory = current }
}

// SetLookPath allows tests to inject a mock LookPath.
// IMPORTANT: Call the returned function in test teardown to restore.
func SetLookPath(lookPathFunc func(string) (string, error)) (restore func()) {
	current := ExecLookPath
	ExecLookPath = lookPathFunc
	return func() { ExecLookPath = current }
}

// --- End Mocking Setup ---

// RunFilter executes an external `jq` command using the configured CommandFactory.
func RunFilter(input []byte, jqFilter string) (string, error) {
	// Use the potentially mocked ExecLookPath
	jqPath, err := ExecLookPath("jq")
	if err != nil {
		return "", fmt.Errorf("failed to find '%s' executable in PATH: %w", "jq", err)
	}

	// Use the configured factory (real or mock) to get a CommandRunner
	cmdRunner := commandFactory(jqPath, "-r", jqFilter) // Use -r for raw string output

	// Assign buffers for capturing output via the interface methods
	var stdout, stderr bytes.Buffer
	cmdRunner.SetStdout(&stdout)
	cmdRunner.SetStderr(&stderr)

	// Provide input via Stdin via the interface method
	cmdRunner.SetStdin(bytes.NewReader(input))

	logging.Logf(logging.Debug, "Executing jq: %s -r '%s'", jqPath, jqFilter)

	// Execute the command via the interface method (could be the real Run or a mock)
	err = cmdRunner.Run()
	if err != nil {
		stderrStr := strings.TrimSpace(stderr.String())
		inputSnippet := string(input)
		if len(inputSnippet) > 100 {
			inputSnippet = inputSnippet[:100] + "..."
		}
		return "", fmt.Errorf("jq command execution failed (filter: '%s', input snippet: '%s'): %w\nstderr: %s", jqFilter, inputSnippet, err, stderrStr)
	}

	return strings.TrimSpace(stdout.String()), nil
}
