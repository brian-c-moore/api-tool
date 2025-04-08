package app

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"

	"api-tool/internal/auth"
	"api-tool/internal/chain" // Depends on chain interface
	"api-tool/internal/config"
	"api-tool/internal/executor" // Depends on executor interface/helpers
	"api-tool/internal/httpclient"
	"api-tool/internal/logging"
	"api-tool/internal/util"
)

// Define common errors for the application layer.
var (
	ErrUsage          = errors.New("usage error") // Use errors.New for sentinel errors
	ErrConfigNotFound = errors.New("configuration file not found")
	ErrMissingArgs    = errors.New("missing required arguments")
)

// RequestOverrides holds command-line overrides for a single request.
type RequestOverrides struct {
	Method  string
	Headers string
	Data    string
}

// --- Interfaces for Testability ---

// configLoader defines the interface for loading configuration.
type configLoader interface {
	Load(filename string) (*config.Config, error)
}

// chainRunner defines the interface for running a chain.
type chainRunner interface {
	Run(ctx context.Context) error
}

// chainRunnerFactory defines the interface for creating a chain runner.
// Takes config and logLevel, returns a chainRunner interface.
type chainRunnerFactory interface {
	New(cfg *config.Config, logLevel int) chainRunner
}

// requestExecutor defines the interface for executing HTTP requests and handling pagination in single request mode.
// Necessary to allow mocking the execution/pagination part of runSingleRequest.
type requestExecutor interface {
	ExecuteRequest(*http.Client, *http.Request, string, map[string]string, config.RetryConfig, int) (*http.Response, []byte, error)
	HandlePagination(*http.Client, *http.Request, config.EndpointConfig, *http.Response, []byte, string, map[string]string, config.RetryConfig, int) (string, error)
}

// --- Default Implementations ---

type defaultConfigLoader struct{}

func (l *defaultConfigLoader) Load(filename string) (*config.Config, error) {
	return config.LoadConfig(filename)
}

type defaultChainRunnerFactory struct{}

// New satisfies the chainRunnerFactory interface by calling the actual chain.NewRunner.
// It returns the concrete *chain.Runner which implicitly satisfies the chainRunner interface.
func (f *defaultChainRunnerFactory) New(cfg *config.Config, logLevel int) chainRunner {
	return chain.NewRunner(cfg, logLevel) // Returns *chain.Runner
}

// defaultRequestExecutor provides the default implementation using the executor package.
type defaultRequestExecutor struct{}

func (e *defaultRequestExecutor) ExecuteRequest(client *http.Client, req *http.Request, effAuth string, creds map[string]string, retry config.RetryConfig, lvl int) (*http.Response, []byte, error) {
	return executor.ExecuteRequest(client, req, effAuth, creds, retry, lvl)
}
func (e *defaultRequestExecutor) HandlePagination(client *http.Client, req *http.Request, epCfg config.EndpointConfig, resp *http.Response, body []byte, effAuth string, creds map[string]string, retry config.RetryConfig, lvl int) (string, error) {
	return executor.HandlePagination(client, req, epCfg, resp, body, effAuth, creds, retry, lvl)
}

// --- AppRunner ---

// AppRunner encapsulates the application's execution logic and dependencies.
type AppRunner struct {
	configLoader       configLoader
	chainRunnerFactory chainRunnerFactory
	requestExecutor    requestExecutor // Added request executor for single mode
}

// AppRunnerOpts allows configuring the AppRunner's dependencies.
type AppRunnerOpts struct {
	ConfigLoader       configLoader
	ChainRunnerFactory chainRunnerFactory
	RequestExecutor    requestExecutor // Added request executor option
}

// NewAppRunner creates a new instance of the application runner with default dependencies.
func NewAppRunner() *AppRunner {
	// Calls NewAppRunnerWithOpts using default implementations.
	return NewAppRunnerWithOpts(AppRunnerOpts{})
}

// NewAppRunnerWithOpts creates a new AppRunner allowing dependency injection.
func NewAppRunnerWithOpts(opts AppRunnerOpts) *AppRunner {
	loader := opts.ConfigLoader
	if loader == nil {
		loader = &defaultConfigLoader{}
	}
	chainFactory := opts.ChainRunnerFactory
	if chainFactory == nil {
		chainFactory = &defaultChainRunnerFactory{}
	}
	// Use provided request executor or default
	reqExec := opts.RequestExecutor
	if reqExec == nil {
		reqExec = &defaultRequestExecutor{}
	}
	return &AppRunner{
		configLoader:       loader,
		chainRunnerFactory: chainFactory,
		requestExecutor:    reqExec, // Set the request executor
	}
}

// usageText defines the command-line help information.
const usageText = `Usage:
  api-tool [options]

Options:
  -config string
        YAML configuration file (default "config.yaml")
  -chain
        Run in chain workflow mode
  -api string
        API name for single request mode
  -endpoint string
        Endpoint name for single request mode
  -method string
        Override HTTP method
  -headers string
        Additional headers (Key:Value,...)
  -data string
        JSON payload for POST/PUT requests
  -loglevel string
        Logging level (none, error, warn, info, debug) (default "info")
  -help
        Show help

Examples:
  Single request mode:
    api-tool -config=config.yaml -api myapi -endpoint getdata -loglevel=debug

  Chain workflow mode:
    api-tool -config=chain.yaml --chain -loglevel=debug
`

// Usage prints the command-line help information to the specified writer.
func (a *AppRunner) Usage(writer io.Writer) {
	fmt.Fprint(writer, usageText)
}

// Run parses command-line arguments and executes the appropriate mode (single request or chain).
func (a *AppRunner) Run(args []string) error {
	fs := flag.NewFlagSet("api-tool", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // Prevent flagset from printing errors/usage

	configFile := fs.String("config", "config.yaml", "YAML configuration file")
	chainMode := fs.Bool("chain", false, "Run in chain workflow mode")
	apiName := fs.String("api", "", "API name for single request mode")
	endpoint := fs.String("endpoint", "", "Endpoint name for single request mode")
	methodFlag := fs.String("method", "", "Override HTTP method")
	headers := fs.String("headers", "", "Additional headers (Key:Value,...)")
	data := fs.String("data", "", "JSON payload for POST/PUT")
	logLevelStr := fs.String("loglevel", "info", "Logging level (none, error, warn, info, debug)")
	helpFlag := fs.Bool("help", false, "Show help")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) { // Use errors.Is for flag.ErrHelp
			a.Usage(os.Stderr) // Use os.Stderr for usage on help request
			return nil         // Successful exit after showing help
		}
		return fmt.Errorf("%w: %v", ErrUsage, err) // Wrap parsing errors
	}

	if *helpFlag || (len(args) == 0 && !anyFlagsSet(fs)) { // Show help if no args *and* no flags were actually set
		a.Usage(os.Stderr)
		return nil // Treat as successful exit
	}

	logLevel := logging.SetupLogging(*logLevelStr) // Setup initial logging level

	// Stat config file *before* loading
	if _, err := os.Stat(*configFile); err != nil {
		if os.IsNotExist(err) {
			// Use standard logger because logging level isn't fully configured yet
			log.Printf("[ERROR] Configuration file '%s' not found.", *configFile)
			return ErrConfigNotFound
		}
		// Other stat error (e.g., permission denied)
		return fmt.Errorf("failed to stat config file '%s': %w", *configFile, err)
	}

	// Load config using the injected loader
	cfg, err := a.configLoader.Load(*configFile)
	if err != nil {
		log.Printf("[ERROR] Error loading configuration '%s': %v", *configFile, err)
		// Don't wrap the loader error further, it should be descriptive enough
		return err
	}

	// Override log level from config if it wasn't explicitly set by flag
	if !isFlagSet(fs, "loglevel") && cfg.Logging.Level != "" {
		logLevel = logging.SetupLogging(cfg.Logging.Level) // Re-setup with config level
	}
	logging.SetLevel(logLevel) // Ensure final level is set

	ctx := context.Background()

	if *chainMode {
		// FIX: Check for cfg.Chain *before* creating the runner
		if cfg.Chain == nil {
			return fmt.Errorf("error: --chain flag used, but no 'chain' section found in config '%s'", *configFile)
		}
		// Use the injected factory to create the chain runner
		runner := a.chainRunnerFactory.New(cfg, logLevel)
		// Now call runChainMode which just runs the runner
		return a.runChainMode(ctx, runner) // Pass only the runner
	}

	// Single Request Mode Logic
	if *apiName == "" || *endpoint == "" {
		logging.Logf(logging.Error, "Error: -api and -endpoint are required in single request mode.")
		return ErrMissingArgs
	}

	overrides := RequestOverrides{
		Method:  *methodFlag,
		Headers: *headers,
		Data:    *data,
	}

	// Pass the full config and the determined log level
	return a.runSingleRequest(ctx, cfg, *apiName, *endpoint, overrides, logLevel)
}

// Helper to check if any flags were actually set by the user
func anyFlagsSet(fs *flag.FlagSet) bool {
	anySet := false
	fs.Visit(func(f *flag.Flag) { // Visit only visits flags that were set
		anySet = true
	})
	return anySet
}

// Helper to check if a specific flag was set
func isFlagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// runChainMode executes the chain workflow using the provided runner instance.
// Removed cfg and configFile args as they are no longer needed after the check in Run.
func (a *AppRunner) runChainMode(ctx context.Context, runner chainRunner) error {
	// Run the chain using the potentially mocked runner
	if err := runner.Run(ctx); err != nil {
		// Log the error before returning, respecting configured level
		logging.Logf(logging.Error, "Chain execution failed: %v", err)
		// Don't wrap again, the runner should provide a good error
		return err
	}
	// Success message logged by main
	return nil
}

// runSingleRequest handles the logic for executing a single API call.
// Uses the injected requestExecutor.
func (a *AppRunner) runSingleRequest(ctx context.Context, cfg *config.Config, apiName, endpointName string, overrides RequestOverrides, logLevel int) error {
	// --- Find API and Endpoint Configuration ---
	apiConf, ok := cfg.APIs[apiName]
	if !ok {
		return fmt.Errorf("API '%s' not found in configuration", apiName)
	}
	endpointConf, ok := apiConf.Endpoints[endpointName]
	if !ok {
		return fmt.Errorf("endpoint '%s' not found in API '%s'", endpointName, apiName)
	}

	// --- Determine Effective Settings ---
	httpMethod := endpointConf.Method // Default to endpoint config
	if overrides.Method != "" {
		httpMethod = overrides.Method // Override with flag
	}
	if httpMethod == "" {
		httpMethod = "GET" // Default method if not specified anywhere
	}

	effectiveAuthType := strings.ToLower(apiConf.AuthType)
	if effectiveAuthType == "" && cfg.Auth.Default != "" {
		effectiveAuthType = strings.ToLower(cfg.Auth.Default)
	}

	// --- Prepare Request Data ---
	// Robust URL joining using url.ResolveReference
	baseURLStr := util.ExpandEnvUniversal(apiConf.BaseURL)
	pathStr := util.ExpandEnvUniversal(endpointConf.Path)
	baseURL, err := url.Parse(baseURLStr)
	if err != nil {
		return fmt.Errorf("failed to parse base URL '%s': %w", baseURLStr, err)
	}
	pathURL, err := url.Parse(pathStr) // Allows path to potentially be absolute
	if err != nil {
		return fmt.Errorf("failed to parse endpoint path '%s': %w", pathStr, err)
	}
	// ResolveReference handles joining correctly, including absolute paths in 'pathStr'
	// and ensuring no double slashes.
	resolvedURL := baseURL.ResolveReference(pathURL).String()

	payloadStr := util.ExpandEnvUniversal(overrides.Data) // Use data from overrides
	payload := []byte(payloadStr)

	// --- Create HTTP Request ---
	var bodyReader io.Reader
	if len(payload) > 0 {
		bodyReader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, httpMethod, resolvedURL, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if len(payload) > 0 {
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(payload)), nil
		}
		if req.Header.Get("Content-Type") == "" && util.LooksLikeJSON(payloadStr) {
			req.Header.Set("Content-Type", "application/json")
			logging.Logf(logging.Debug, "Auto-set Content-Type to application/json")
		}
	}

	if overrides.Headers != "" {
		for _, pair := range strings.Split(overrides.Headers, ",") {
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid header format in -headers flag: '%s'", pair)
			}
			req.Header.Set(strings.TrimSpace(util.ExpandEnvUniversal(parts[0])), strings.TrimSpace(util.ExpandEnvUniversal(parts[1])))
		}
	}

	// --- Authentication ---
	apiToken := auth.GetAPIToken()
	var creds map[string]string
	if cfg.Auth.Credentials != nil {
		creds = cfg.Auth.Credentials
	} else {
		creds = make(map[string]string)
	}
	if err := auth.ApplyAuthHeaders(req, effectiveAuthType, creds, apiToken); err != nil {
		return fmt.Errorf("failed to apply auth headers: %w", err)
	}

	// --- Apply Initial Pagination Params if Forced ---
	paginationConfigured := endpointConf.Pagination != nil && (endpointConf.Pagination.Type == "offset" || endpointConf.Pagination.Type == "page")
	if paginationConfigured && endpointConf.Pagination.ForceInitialPaginationParams {
		pagCfgCopy := *endpointConf.Pagination
		executor.ApplyPaginationDefaults(&pagCfgCopy, strings.ToLower(pagCfgCopy.Type)) // Ensure defaults applied

		if pagCfgCopy.Type == "offset" || pagCfgCopy.Type == "page" {
			logging.Logf(logging.Info, "Forcing initial pagination parameters for %s %s", req.Method, req.URL.String())
			err := executor.ModifyRequestForInitialPage(&pagCfgCopy, req) // Pass config pointer
			if err != nil {
				return fmt.Errorf("failed to apply initial pagination parameters: %w", err)
			}
			logging.Logf(logging.Debug, "Request modified for initial pagination params. New URL: %s", req.URL.String())
			// Body logging might be too verbose here, but could be added
		}
	}

	// --- Create HTTP Client ---
	var jar http.CookieJar
	if apiConf.CookieJar {
		jar, err = cookiejar.New(nil)
		if err != nil {
			return fmt.Errorf("failed to create cookie jar: %w", err)
		}
		logging.Logf(logging.Info, "Cookie jar enabled for API '%s'", apiName)
	}
	// Pass cfg.FipsMode to NewClient
	client, err := httpclient.NewClient(&apiConf, &cfg.Auth, jar, cfg.FipsMode)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// --- Execute Request ---
	logging.Logf(logging.Debug, "Sending request: %s %s", req.Method, req.URL.String())
	if len(req.Header) > 0 {
		logging.Logf(logging.Debug, "Request Headers: %v", req.Header)
	}
	if len(payload) > 0 {
		logging.Logf(logging.Debug, "Request Payload Snippet: %s", util.Snippet(payload))
	}

	// Use the injected requestExecutor
	resp, bodyBytes, err := a.requestExecutor.ExecuteRequest(client, req, effectiveAuthType, creds, cfg.Retry, logLevel)
	if err != nil {
		logging.Logf(logging.Error, "Request execution failed: %v", err)
		return fmt.Errorf("request execution failed: %w", err)
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	logging.Logf(logging.Debug, "Response Status: %d", resp.StatusCode)
	logging.Logf(logging.Debug, "Response Headers: %v", resp.Header)
	logging.Logf(logging.Debug, "Response Body Snippet: %s", util.Snippet(bodyBytes))
	if jar != nil {
		httpclient.LogCookieJar(jar, apiConf.BaseURL, logLevel)
	}

	// --- Handle Pagination ---
	var finalBody string
	var pagErr error
	paginationConfigured = endpointConf.Pagination != nil && endpointConf.Pagination.Type != "" && endpointConf.Pagination.Type != "none" // Re-check type isn't none

	if paginationConfigured {
		paginationType := strings.ToLower(endpointConf.Pagination.Type)
		logging.Logf(logging.Info, "Handling '%s' pagination...", paginationType)
		// Use the injected requestExecutor for pagination as well
		paginatedBody, errP := a.requestExecutor.HandlePagination(client, req, endpointConf, resp, bodyBytes, effectiveAuthType, creds, cfg.Retry, logLevel)
		if errP != nil {
			finalBody = paginatedBody
			pagErr = errP
			logging.Logf(logging.Error, "Single Request: Pagination failed: %v. Displaying data collected so far.", pagErr)
		} else {
			finalBody = paginatedBody
		}
	} else {
		finalBody = string(bodyBytes)
	}

	// --- Output Results ---
	fmt.Println(finalBody) // Use primary output for the result body

	if pagErr != nil {
		return fmt.Errorf("request completed but pagination failed: %w", pagErr)
	}

	return nil
}