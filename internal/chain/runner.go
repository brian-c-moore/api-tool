package chain

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"

	"api-tool/internal/auth"
	"api-tool/internal/config"
	"api-tool/internal/executor"
	"api-tool/internal/httpclient"
	"api-tool/internal/jq"
	"api-tool/internal/logging"
	"api-tool/internal/template"
	"api-tool/internal/util"
)

// --- Interfaces for Dependencies ---

// httpClientProvider defines the interface for creating HTTP clients.
type httpClientProvider interface {
	NewClient(apiCfg *config.APIConfig, authCfg *config.AuthConfig, jar http.CookieJar, fipsMode bool) (*http.Client, error)
}

// requestExecutor defines the interface for executing HTTP requests and handling pagination.
// It is responsible for reading the response body and returning it as bytes on success.
type requestExecutor interface {
	ExecuteRequest(*http.Client, *http.Request, string, map[string]string, config.RetryConfig, int) (*http.Response, []byte, error)
	HandlePagination(*http.Client, *http.Request, config.EndpointConfig, *http.Response, []byte, string, map[string]string, config.RetryConfig, int) (string, error)
}

// jqRunner defines the interface for running JQ filters.
type jqRunner interface {
	RunFilter([]byte, string) (string, error)
}

// FileReader defines the interface for reading files and getting file status.
// This allows mocking file system interactions.
type FileReader interface {
	Open(name string) (io.ReadCloser, error)
	Stat(name string) (fs.FileInfo, error)
}

// FileWriter defines the interface for writing files.
// This allows mocking file system interactions.
type FileWriter interface {
	// WriteFile writes data to a file named by filename.
	// If the file does not exist, WriteFile creates it with permissions perm (before umask);
	// otherwise WriteFile truncates it before writing.
	WriteFile(filename string, data []byte, perm fs.FileMode) error
	// OpenFile is still needed for potential future features or different write patterns,
	// but WriteFile is preferred for atomic writes of complete data.
	OpenFile(name string, flag int, perm fs.FileMode) (io.WriteCloser, error)
}

// --- Default Implementations ---

// defaultHttpClientProvider provides the default implementation using the httpclient package.
type defaultHttpClientProvider struct{}

func (p *defaultHttpClientProvider) NewClient(apiCfg *config.APIConfig, authCfg *config.AuthConfig, jar http.CookieJar, fipsMode bool) (*http.Client, error) {
	return httpclient.NewClient(apiCfg, authCfg, jar, fipsMode)
}

// defaultRequestExecutor provides the default implementation using the executor package.
type defaultRequestExecutor struct{}

func (e *defaultRequestExecutor) ExecuteRequest(client *http.Client, req *http.Request, effAuth string, creds map[string]string, retry config.RetryConfig, lvl int) (*http.Response, []byte, error) {
	return executor.ExecuteRequest(client, req, effAuth, creds, retry, lvl)
}
func (e *defaultRequestExecutor) HandlePagination(client *http.Client, req *http.Request, epCfg config.EndpointConfig, resp *http.Response, body []byte, effAuth string, creds map[string]string, retry config.RetryConfig, lvl int) (string, error) {
	return executor.HandlePagination(client, req, epCfg, resp, body, effAuth, creds, retry, lvl)
}

// defaultJqRunner provides the default implementation using the jq package.
type defaultJqRunner struct{}

func (r *defaultJqRunner) RunFilter(input []byte, jqFilter string) (string, error) {
	return jq.RunFilter(input, jqFilter)
}

// defaultFileReader provides the default implementation using the os package.
type defaultFileReader struct{}

func (d *defaultFileReader) Open(name string) (io.ReadCloser, error) { return os.Open(name) }
func (d *defaultFileReader) Stat(name string) (fs.FileInfo, error)   { return os.Stat(name) }

// defaultFileWriter provides the default implementation using the os package.
type defaultFileWriter struct{}

func (d *defaultFileWriter) WriteFile(filename string, data []byte, perm fs.FileMode) error {
	// Ensure directory exists before writing. This mimics os.WriteFile behavior partially,
	// as os.WriteFile itself doesn't create directories.
	dir := filepath.Dir(filename)
	if mkDirErr := os.MkdirAll(dir, 0755); mkDirErr != nil {
		// Check if the path exists but isn't a directory.
		if info, statErr := os.Stat(dir); statErr == nil && !info.IsDir() {
			return fmt.Errorf("cannot create directory for output file: path '%s' exists but is not a directory", dir)
		}
		return fmt.Errorf("failed to create output directory '%s': %w", dir, mkDirErr)
	}
	return os.WriteFile(filename, data, perm)
}
func (d *defaultFileWriter) OpenFile(name string, flag int, perm fs.FileMode) (io.WriteCloser, error) {
	// Ensure directory exists before opening (useful for O_CREATE).
	dir := filepath.Dir(name)
	if flag&os.O_CREATE != 0 { // Only create dir if file creation is intended
		if mkDirErr := os.MkdirAll(dir, 0755); mkDirErr != nil {
			if info, statErr := os.Stat(dir); statErr == nil && !info.IsDir() {
				return nil, fmt.Errorf("cannot create directory for output file: path '%s' exists but is not a directory", dir)
			}
			return nil, fmt.Errorf("failed to create output directory '%s': %w", dir, mkDirErr)
		}
	}
	return os.OpenFile(name, flag, perm)
}

// --- Runner Struct ---

// Runner encapsulates the state and dependencies for executing a chain of API calls or filters.
type Runner struct {
	cfg                *config.Config
	state              *State
	logLevel           int
	httpClientProvider httpClientProvider
	requestExecutor    requestExecutor
	jqRunner           jqRunner
	fileWriter         FileWriter
	fileReader         FileReader
}

// RunnerOpts allows configuring the Runner's dependencies for testing or custom behavior.
type RunnerOpts struct {
	HttpClientProvider httpClientProvider
	RequestExecutor    requestExecutor
	JqRunner           jqRunner
	FileWriter         FileWriter
	FileReader         FileReader
}

// NewRunner creates a new chain runner instance with default dependencies.
func NewRunner(cfg *config.Config, logLevel int) *Runner {
	return NewRunnerWithOpts(cfg, logLevel, RunnerOpts{})
}

// NewRunnerWithOpts creates a new chain runner instance with injected dependencies.
// This pattern allows for replacing default implementations with mocks during testing.
func NewRunnerWithOpts(cfg *config.Config, logLevel int, opts RunnerOpts) *Runner {
	provider := opts.HttpClientProvider
	if provider == nil {
		provider = &defaultHttpClientProvider{}
	}
	executor := opts.RequestExecutor
	if executor == nil {
		executor = &defaultRequestExecutor{}
	}
	jq := opts.JqRunner
	if jq == nil {
		jq = &defaultJqRunner{}
	}
	writer := opts.FileWriter
	if writer == nil {
		writer = &defaultFileWriter{}
	}
	reader := opts.FileReader
	if reader == nil {
		reader = &defaultFileReader{}
	}
	return &Runner{
		cfg:                cfg,
		state:              NewState(),
		logLevel:           logLevel,
		httpClientProvider: provider,
		requestExecutor:    executor,
		jqRunner:           jq,
		fileWriter:         writer,
		fileReader:         reader,
	}
}

// Run executes the configured chain workflow step-by-step.
// It initializes the state, handles context cancellation, executes each step,
// and optionally writes output at the end.
func (r *Runner) Run(ctx context.Context) error {
	if r.cfg.Chain == nil {
		return fmt.Errorf("chain configuration is missing")
	}
	// Initialize state with OS environment variables and configured chain variables.
	r.state.MergeOSEnv()
	r.state.MergeMap(r.cfg.Chain.Variables)
	if r.logLevel >= logging.Debug {
		logging.Logf(logging.Debug, "Initial State: %v", r.state.GetAll())
	}
	// Create a persistent cookie jar for use across steps if CookieJar is enabled for any API.
	persistentJar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("create persistent jar: %w", err)
	}

	// Execute each step sequentially.
	for i, step := range r.cfg.Chain.Steps {
		stepName := step.Name
		if stepName == "" {
			stepName = fmt.Sprintf("step_%d", i+1)
		}
		logging.Logf(logging.Info, "Executing Step: %s", stepName)

		// Check for context cancellation before executing the step.
		if ctx.Err() != nil {
			return fmt.Errorf("chain cancelled during step '%s': %w", stepName, ctx.Err())
		}

		var stepErr error
		// Determine step type and execute.
		if step.Request != nil {
			stepErr = r.executeRequestStep(ctx, stepName, step, persistentJar)
		} else if step.Filter != nil {
			stepErr = r.executeFilterStep(stepName, step)
		} else {
			stepErr = fmt.Errorf("step '%s' has neither request nor filter defined", stepName)
		}
		// Fail fast if a step encounters an error.
		if stepErr != nil {
			return fmt.Errorf("error in step '%s': %w", stepName, stepErr)
		}
	}

	// Write output if configured.
	if err := r.writeOutput(); err != nil {
		return err
	}

	logging.Logf(logging.Info, "Chain execution completed.")
	return nil
}

// executeRequestStep handles a single API request step within the chain.
// It renders templates, prepares the request body (data, file upload, multipart),
// applies authentication, executes the request (via executor), handles downloads
// or pagination/extraction, and updates the chain state.
func (r *Runner) executeRequestStep(ctx context.Context, stepName string, step config.ChainStep, persistentJar http.CookieJar) (err error) {
	reqCfg := step.Request
	// Find API and Endpoint configuration.
	apiConf, ok := r.cfg.APIs[reqCfg.API]
	if !ok {
		return fmt.Errorf("API '%s' not found in configuration", reqCfg.API)
	}
	endpointConf, ok := apiConf.Endpoints[reqCfg.Endpoint]
	if !ok {
		return fmt.Errorf("endpoint '%s' not found in API '%s'", reqCfg.Endpoint, reqCfg.API)
	}

	// Render headers using current state.
	renderedHeaders := make(map[string]string)
	for key, valTmpl := range reqCfg.Headers {
		renderedVal, tmplErr := template.Render("header_"+key+"_"+stepName, valTmpl, r.state.GetAll())
		if tmplErr != nil {
			return fmt.Errorf("failed to render header template for '%s': %w", key, tmplErr)
		}
		renderedHeaders[key] = renderedVal
	}

	// Expand environment variables and render templates in URL path.
	baseURLExpanded := util.ExpandEnvUniversal(apiConf.BaseURL)
	pathTemplateExpanded := util.ExpandEnvUniversal(endpointConf.Path)
	fullPathTemplate := baseURLExpanded + pathTemplateExpanded
	renderedURL, urlErr := template.Render("endpointPath_"+stepName, fullPathTemplate, r.state.GetAll())
	if urlErr != nil {
		return fmt.Errorf("failed to render URL template '%s': %w", fullPathTemplate, urlErr)
	}

	// --- Prepare Request Body ---
	var bodyReader io.Reader = nil        // The reader passed to http.NewRequest
	var contentTypeHeader string = ""      // Potential Content-Type based on body type
	var getBody func() (io.ReadCloser, error) // Function to get a fresh body reader (for retries)
	var contentLength int64 = -1         // Request Content-Length
	var finalBodyBytes []byte            // Store final constructed body bytes if needed for GetBody

	if reqCfg.UploadBodyFrom != "" {
		// Handle raw file upload.
		renderedPath, pathErr := template.Render("uploadPath_"+stepName, reqCfg.UploadBodyFrom, r.state.GetAll())
		if pathErr != nil {
			return fmt.Errorf("failed to render upload path template '%s': %w", reqCfg.UploadBodyFrom, pathErr)
		}
		renderedPath = util.ExpandEnvUniversal(renderedPath)
		logging.Logf(logging.Debug, "Step '%s': Uploading body from file: %s", stepName, renderedPath)

		// Use FileReader interface to open and stat the file.
		fileReaderImpl, openErr := r.fileReader.Open(renderedPath) // Renamed variable
		if openErr != nil {
			return fmt.Errorf("failed to open upload file '%s': %w", renderedPath, openErr)
		}
		// Use a named variable for the closer to ensure the correct instance is closed.
		var fileToClose io.Closer = fileReaderImpl
		// Defer close, handling potential error accumulation.
		defer func() {
			if fileToClose != nil {
				closeErr := fileToClose.Close()
				if closeErr != nil && err == nil { // Only assign if no prior error
					err = fmt.Errorf("failed to close upload file '%s': %w", renderedPath, closeErr)
				} else if closeErr != nil { // Log subsequent close errors
					logging.Logf(logging.Error, "Step '%s': Error closing upload file '%s' (deferred): %v", stepName, renderedPath, closeErr)
				}
			}
		}()

		fileInfo, statErr := r.fileReader.Stat(renderedPath)
		if statErr != nil {
			return fmt.Errorf("failed to get file info for '%s': %w", renderedPath, statErr)
		}

		bodyReader = fileReaderImpl // Use the opened file as the body reader
		contentTypeHeader = "application/octet-stream" // Default content type for raw upload
		contentLength = fileInfo.Size()
		// Provide a GetBody function that re-opens the file.
		getBody = func() (io.ReadCloser, error) {
			return r.fileReader.Open(renderedPath)
		}

	} else if len(reqCfg.FileFields) > 0 || len(reqCfg.FormData) > 0 {
		// Handle multipart/form-data request.
		logging.Logf(logging.Debug, "Step '%s': Preparing multipart form data", stepName)
		bodyBuf := &bytes.Buffer{}
		mpWriter := multipart.NewWriter(bodyBuf)

		// Write regular form fields.
		for key, valTmpl := range reqCfg.FormData {
			renderedVal, tmplErr := template.Render("form_"+key+"_"+stepName, valTmpl, r.state.GetAll())
			if tmplErr != nil {
				return fmt.Errorf("failed to render form field template '%s': %w", key, tmplErr)
			}
			if writeErr := mpWriter.WriteField(key, renderedVal); writeErr != nil {
				return fmt.Errorf("failed to write form field '%s': %w", key, writeErr)
			}
		}

		// Write file fields.
		var filesToClose []io.Closer
		defer func() { // Ensure all opened files are closed.
			for _, f := range filesToClose {
				f.Close() // Ignore close errors in defer for simplicity here
			}
		}()
		for fieldName, filePathTmpl := range reqCfg.FileFields {
			renderedPath, pathErr := template.Render("fpath_"+fieldName+"_"+stepName, filePathTmpl, r.state.GetAll())
			if pathErr != nil {
				return fmt.Errorf("failed to render file path template for field '%s': %w", fieldName, pathErr)
			}
			renderedPath = util.ExpandEnvUniversal(renderedPath)

			file, openErr := r.fileReader.Open(renderedPath)
			if openErr != nil {
				return fmt.Errorf("failed to open multipart file '%s' for field '%s': %w", renderedPath, fieldName, openErr)
			}
			filesToClose = append(filesToClose, file) // Add to list for deferred closing

			part, createErr := mpWriter.CreateFormFile(fieldName, filepath.Base(renderedPath))
			if createErr != nil {
				return fmt.Errorf("failed to create form file for field '%s': %w", fieldName, createErr)
			}
			_, copyErr := io.Copy(part, file)
			if copyErr != nil {
				return fmt.Errorf("failed to copy multipart file content for field '%s': %w", fieldName, copyErr)
			}
			logging.Logf(logging.Debug, "Step '%s': Added multipart file '%s' from path '%s' as field '%s'", stepName, filepath.Base(renderedPath), renderedPath, fieldName)
		}

		// Close the multipart writer to finalize the body.
		if closeErr := mpWriter.Close(); closeErr != nil {
			return fmt.Errorf("failed to close multipart writer: %w", closeErr)
		}

		finalBodyBytes = bodyBuf.Bytes() // Store the complete multipart body
		bodyReader = bytes.NewReader(finalBodyBytes)
		contentTypeHeader = mpWriter.FormDataContentType() // Get the correct Content-Type with boundary
		contentLength = int64(len(finalBodyBytes))
		// Provide GetBody using the stored bytes.
		getBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(finalBodyBytes)), nil
		}

	} else if reqCfg.Data != "" {
		// Handle request body from 'data' field.
		renderedData, tmplErr := template.Render("data_"+stepName, reqCfg.Data, r.state.GetAll())
		if tmplErr != nil {
			return fmt.Errorf("failed to render data template: %w", tmplErr)
		}
		finalBodyBytes = []byte(renderedData)
		bodyReader = bytes.NewReader(finalBodyBytes)
		contentLength = int64(len(finalBodyBytes))
		// Auto-detect JSON content type if not explicitly set in headers.
		if _, exists := renderedHeaders["Content-Type"]; !exists && util.LooksLikeJSON(renderedData) {
			contentTypeHeader = "application/json"
			logging.Logf(logging.Debug, "Step '%s': Auto-detected Content-Type: application/json", stepName)
		}
		// Provide GetBody using the stored bytes.
		getBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(finalBodyBytes)), nil
		}
	}
	// --- End Request Body Preparation ---

	// Determine HTTP method.
	method := reqCfg.Method
	if method == "" {
		method = endpointConf.Method
	}
	if method == "" { // Default to GET if still not specified.
		method = "GET"
	}

	// Create the HTTP request object.
	req, reqErr := http.NewRequestWithContext(ctx, method, renderedURL, bodyReader)
	if reqErr != nil {
		return fmt.Errorf("failed to create HTTP request: %w", reqErr)
	}
	// Set ContentLength and GetBody if determined.
	if contentLength >= 0 {
		req.ContentLength = contentLength
	}
	if getBody != nil {
		req.GetBody = getBody
	}
	// Set Content-Type header if determined and not already set.
	if contentTypeHeader != "" {
		if _, exists := renderedHeaders["Content-Type"]; !exists {
			req.Header.Set("Content-Type", contentTypeHeader)
		}
	}
	// Set explicitly configured headers, potentially overwriting auto-detected ones.
	for key, val := range renderedHeaders {
		req.Header.Set(key, val)
	}

	// Determine and apply authentication.
	effectiveAuthType := strings.ToLower(apiConf.AuthType)
	if effectiveAuthType == "" && r.cfg.Auth.Default != "" {
		effectiveAuthType = strings.ToLower(r.cfg.Auth.Default)
	}
	apiToken, _ := r.state.Get("API_TOKEN") // Check state first for token
	if apiToken == "" {
		apiToken = auth.GetAPIToken() // Fallback to environment variable
	}
	credentials := r.cfg.Auth.Credentials
	if credentials == nil { // Ensure credentials map is not nil for auth functions
		credentials = make(map[string]string)
	}
	if authErr := auth.ApplyAuthHeaders(req, effectiveAuthType, credentials, apiToken); authErr != nil {
		return fmt.Errorf("failed to apply authentication headers: %w", authErr)
	}

	// Select appropriate cookie jar (persistent or temporary).
	var clientJar http.CookieJar
	if apiConf.CookieJar {
		clientJar = persistentJar // Use the jar passed down the chain
	}

	// Create HTTP client using the provider.
	client, clientErr := r.httpClientProvider.NewClient(&apiConf, &r.cfg.Auth, clientJar, r.cfg.FipsMode)
	if clientErr != nil {
		return fmt.Errorf("failed to create HTTP client: %w", clientErr)
	}

	// Execute the request using the executor.
	logging.Logf(logging.Debug, "Step '%s': Sending %s %s", stepName, req.Method, req.URL.String())
	resp, initialBodyBytes, execErr := r.requestExecutor.ExecuteRequest(client, req, effectiveAuthType, credentials, r.cfg.Retry, r.logLevel)

	// --- Process Response ---
	// Ensure the response body (if it exists) is closed eventually, unless it's passed to pagination.
	if resp != nil && resp.Body != nil {
		// The body will be closed either by the download logic consuming it,
		// or by the pagination logic, or by this defer if neither runs or an error occurs before they consume it.
		defer resp.Body.Close()
	}

	// Handle download case first.
	if reqCfg.DownloadTo != "" {
		if execErr != nil {
			return execErr // Return execution error directly if download was intended
		}
		if resp == nil {
			return fmt.Errorf("internal error: received nil response from executor during download step")
		}

		// Render download path template.
		renderedPath, tmplErr := template.Render("dlPath_"+stepName, reqCfg.DownloadTo, r.state.GetAll())
		if tmplErr != nil {
			return fmt.Errorf("failed to render download path template '%s': %w", reqCfg.DownloadTo, tmplErr)
		}
		renderedPath = util.ExpandEnvUniversal(renderedPath)
		logging.Logf(logging.Info, "Step '%s': Downloading (Status %d) to: %s", stepName, resp.StatusCode, renderedPath)

		// Use the FileWriter interface to write the downloaded bytes.
		// The default implementation handles directory creation.
		// Use 0644 as a standard permission for downloaded files.
		writeErr := r.fileWriter.WriteFile(renderedPath, initialBodyBytes, 0644)
		if writeErr != nil {
			return fmt.Errorf("failed writing download file '%s': %w", renderedPath, writeErr)
		}

		bytesWritten := len(initialBodyBytes) // Get length from the byte slice
		logging.Logf(logging.Info, "Step '%s': Downloaded %d bytes to %s", stepName, bytesWritten, renderedPath)

		// Extract header data (body extraction is invalid here).
		if extractErr := r.extractData(stepName, step, resp, ""); extractErr != nil {
			return extractErr // Return extraction error
		}
		return nil // Download successful

	} else { // Handle pagination and/or extraction case.
		if execErr != nil {
			return execErr // Return execution error
		}
		if resp == nil {
			return fmt.Errorf("internal error: received nil response from executor during extract/paginate step")
		}

		var finalBodyString string
		var pagErr error
		// Check if pagination is configured for the endpoint.
		if endpointConf.Pagination != nil && endpointConf.Pagination.Type != "" && endpointConf.Pagination.Type != "none" {
			paginationType := strings.ToLower(endpointConf.Pagination.Type)
			logging.Logf(logging.Info, "Step '%s': Handling '%s' pagination...", stepName, paginationType)
			// Call the executor's pagination handler.
			// Note: HandlePagination now conceptually "owns" the response and its body lifecycle if it runs.
			paginatedBody, pErr := r.requestExecutor.HandlePagination(client, req, endpointConf, resp, initialBodyBytes, effectiveAuthType, credentials, r.cfg.Retry, r.logLevel)
			if pErr != nil {
				// Pagination failed, but may have partial results.
				finalBodyString = paginatedBody // Use partial results if available
				pagErr = pErr                   // Store pagination error
				logging.Logf(logging.Error, "Step '%s': Pagination failed: %v. Processing results obtained so far.", stepName, pagErr)
			} else {
				// Pagination successful.
				finalBodyString = paginatedBody
			}
		} else {
			// No pagination, use the initial response body bytes.
			if initialBodyBytes == nil {
				finalBodyString = ""
			} else {
				finalBodyString = string(initialBodyBytes)
			}
		}

		// Extract data from the final body (either initial or paginated) and headers.
		if extractErr := r.extractData(stepName, step, resp, finalBodyString); extractErr != nil {
			return extractErr // Return extraction error
		}
		// If pagination failed partially, return that error now after extraction.
		if pagErr != nil {
			return fmt.Errorf("pagination failed for step '%s': %w", stepName, pagErr)
		}
		return nil // Success
	}
}

// executeFilterStep handles a local jq filtering step.
// It renders templates for input and filter, executes jq, and extracts results.
func (r *Runner) executeFilterStep(stepName string, step config.ChainStep) error {
	filterCfg := step.Filter
	// Render input template.
	renderedInput, err := template.Render("filterInput_"+stepName, filterCfg.Input, r.state.GetAll())
	if err != nil {
		return fmt.Errorf("rendering filter input template: %w", err)
	}
	// Render jq filter template.
	renderedJqFilter, err := template.Render("jqFilter_"+stepName, filterCfg.Jq, r.state.GetAll())
	if err != nil {
		return fmt.Errorf("rendering jq filter template: %w", err)
	}

	logging.Logf(logging.Debug, "Step '%s': Running jq filter '%s' on input snippet: %s", stepName, renderedJqFilter, util.Snippet([]byte(renderedInput)))
	// Execute jq filter using the runner.
	result, err := r.jqRunner.RunFilter([]byte(renderedInput), renderedJqFilter)
	if err != nil {
		return fmt.Errorf("jq execution failed: %w", err)
	}
	logging.Logf(logging.Debug, "Step '%s': Filter result snippet: %s", stepName, util.Snippet([]byte(result)))

	// Extract data from the filter result.
	if err := r.extractDataFromFilter(stepName, step, result); err != nil {
		return err
	}
	return nil
}

// extractData handles variable extraction from API response headers or body.
// It iterates through the 'extract' map, determines if it's a header or body extraction,
// performs the extraction, and updates the chain state.
func (r *Runner) extractData(stepName string, step config.ChainStep, resp *http.Response, body string) error {
	if resp == nil {
		return fmt.Errorf("internal error: nil response provided to extractData")
	}
	for varName, extractionExpr := range step.Extract {
		var extractedValue string
		var extractErr error
		trimmedExpr := strings.TrimSpace(extractionExpr)

		if strings.HasPrefix(trimmedExpr, "header:") {
			// Extract from header using regex.
			extractedValue, extractErr = executor.ExtractHeaderValue(resp, trimmedExpr)
			if extractErr != nil {
				// Improve error context.
				extractErr = fmt.Errorf("extracting header for variable '%s' using expression '%s': %w", varName, extractionExpr, extractErr)
			} else {
				logging.Logf(logging.Info, "Step '%s': Extracted Variable '%s' = '%s' (from Header)", stepName, varName, util.Snippet([]byte(extractedValue)))
			}
		} else {
			// Extract from body using JQ filter.
			if body == "" && step.Request != nil && step.Request.DownloadTo != "" {
				// Special case: Body extraction attempted on a download step (which is invalid).
				// This should be caught by validation, but double-check here.
				extractErr = fmt.Errorf("cannot extract body variable '%s': step involves download_to, body is not available for JQ extraction", varName)
			} else if body == "" {
				// Body is empty or was consumed (e.g., non-2xx status without pagination).
				extractErr = fmt.Errorf("cannot extract body variable '%s': response body is empty or was consumed (status: %d)", varName, resp.StatusCode)
			} else {
				// Run JQ filter.
				extractedValue, extractErr = r.jqRunner.RunFilter([]byte(body), trimmedExpr)
				if extractErr != nil {
					// Improve error context.
					extractErr = fmt.Errorf("extracting body variable '%s' using JQ filter '%s': %w", varName, trimmedExpr, extractErr)
				} else {
					logging.Logf(logging.Info, "Step '%s': Extracted Variable '%s' = '%s' (from Body JQ)", stepName, varName, util.Snippet([]byte(extractedValue)))
				}
			}
		}

		// If any extraction failed, return the error immediately.
		if extractErr != nil {
			return extractErr
		}
		// Update the chain state with the extracted value.
		r.state.Set(varName, extractedValue)
	}
	return nil
}

// extractDataFromFilter handles variable extraction after a filter step.
// It allows assigning the entire filter result or rendering a template using the result and current state.
func (r *Runner) extractDataFromFilter(stepName string, step config.ChainStep, filterResult string) error {
	for varName, extractionValueTmpl := range step.Extract {
		var finalValue string
		if strings.TrimSpace(extractionValueTmpl) == "{{result}}" {
			// Direct assignment of filter result.
			finalValue = filterResult
		} else {
			// Render a template using state + filter result.
			data := r.state.GetAll()
			data["result"] = filterResult // Add the filter result to the template data context.
			renderedVal, err := template.Render("filterExtract_"+varName+"_"+stepName, extractionValueTmpl, data)
			if err != nil {
				return fmt.Errorf("rendering filter extract template '%s' for variable '%s': %w", extractionValueTmpl, varName, err)
			}
			finalValue = renderedVal
		}
		logging.Logf(logging.Info, "Step '%s': Assigned Variable '%s' = '%s' (from Filter Result/Template)", stepName, varName, util.Snippet([]byte(finalValue)))
		r.state.Set(varName, finalValue) // Update state.
	}
	return nil
}

// writeOutput handles writing a specified chain variable to a file at the end of the chain.
// It renders the file path template, ensures the directory exists, and writes the variable value.
func (r *Runner) writeOutput() error {
	// Check if output configuration exists.
	if r.cfg.Chain.Output == nil || r.cfg.Chain.Output.File == "" || r.cfg.Chain.Output.Var == "" {
		return nil // No output configured, nothing to do.
	}
	outputVar := r.cfg.Chain.Output.Var
	val, found := r.state.Get(outputVar)
	if !found {
		// Log a warning if the specified output variable wasn't found in the final state.
		logging.Logf(logging.Warning, "Output variable '%s' specified in config was not found in the final chain state. No file written.", outputVar)
		return nil // Not necessarily an error, just nothing to write.
	}

	// Render the output file path template.
	filePathTmpl := r.cfg.Chain.Output.File
	filePath, err := template.Render("outputFilePath", filePathTmpl, r.state.GetAll())
	if err != nil {
		return fmt.Errorf("failed to render output file path template '%s': %w", filePathTmpl, err)
	}
	filePath = util.ExpandEnvUniversal(filePath) // Expand environment variables in the path.

	// Ensure the output directory exists (handled by default WriteFile impl).
	// Write the variable value to the file using the FileWriter interface.
	err = r.fileWriter.WriteFile(filePath, []byte(val), 0644)
	if err != nil {
		return fmt.Errorf("failed to write output file '%s': %w", filePath, err)
	}

	logging.Logf(logging.Info, "Successfully wrote output variable '%s' to file '%s'", outputVar, filePath)
	return nil
}