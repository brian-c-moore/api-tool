package config

import (
	"os"
	"path/filepath"
	"strings" // Import needed for constructing test YAML
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create a temporary config file for testing (from original)
func createTempConfigFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	filePath := filepath.Join(dir, "config.yaml")
	err := os.WriteFile(filePath, []byte(content), 0644)
	require.NoError(t, err, "Failed to create temporary config file")
	return filePath
}

// TestLoadConfig_ValidCases tests successful loading and parsing of valid configurations. (from original)
func TestLoadConfig_ValidCases(t *testing.T) {
	t.Run("Minimal Valid Config", func(t *testing.T) {
		validYAML := `
retry: { max_attempts: 1, backoff_seconds: 1 }
logging: { level: info }
apis:
  testapi:
    base_url: http://example.com
    endpoints:
      get_data: { path: /data }
`
		filePath := createTempConfigFile(t, validYAML)
		cfg, err := LoadConfig(filePath)
		require.NoError(t, err)
		require.NotNil(t, cfg)
		assert.Equal(t, 1, cfg.Retry.MaxAttempts)
		assert.Equal(t, 1, cfg.Retry.Backoff)
		assert.Equal(t, "info", cfg.Logging.Level)
		assert.Contains(t, cfg.APIs, "testapi")
		assert.Equal(t, "http://example.com", cfg.APIs["testapi"].BaseURL)
		assert.Contains(t, cfg.APIs["testapi"].Endpoints, "get_data")
		assert.Nil(t, cfg.Chain, "Chain should be nil when not defined")
	})

	t.Run("Config with Chain", func(t *testing.T) {
		// This test case now also implicitly tests valid file handling configs if included
		// Validation for download + header extract fixed, so this should pass.
		validYAML := `
retry: { max_attempts: 3, backoff_seconds: 5 }
logging: { level: debug }
auth:
  default: basic
  credentials: { username: user, password: pass }
apis:
  api1:
    base_url: https://api1.test
    auth_type: none # Override default
    endpoints:
      ep1: { path: /path1, method: GET }
      ep2: { path: /upload } # Default GET, ok here
chain:
  variables: { initial_var: value1, outfile: out.txt }
  steps:
    - name: step1
      request: { api: api1, endpoint: ep1 } # Simple request
      extract: { data_id: .id }
    - name: step_download
      request:
        api: api1
        endpoint: ep1 # GET method suitable for download
        download_to: file.dat
      extract:
        req_id: header:X-Req-ID:(.*) # Header extract ok with download
    - name: step_upload
      request:
        api: api1
        endpoint: ep2 # Endpoint default GET, but method overridden
        method: POST
        upload_body_from: data.bin
  output: { file: "{{.outfile}}", var: data_id }
`
		filePath := createTempConfigFile(t, validYAML)
		cfg, err := LoadConfig(filePath)
		// Expect NO error now that validation is fixed
		require.NoError(t, err, "Expected no error for valid config with chain (download + header extract), got: %v", err)
		require.NotNil(t, cfg)
		assert.Equal(t, 3, cfg.Retry.MaxAttempts)
		assert.Equal(t, 5, cfg.Retry.Backoff)
		assert.Equal(t, "debug", cfg.Logging.Level)
		assert.Equal(t, "basic", cfg.Auth.Default)
		assert.Equal(t, "user", cfg.Auth.Credentials["username"])
		assert.Equal(t, "none", cfg.APIs["api1"].AuthType)
		require.NotNil(t, cfg.Chain)
		assert.Equal(t, "value1", cfg.Chain.Variables["initial_var"])
		require.Len(t, cfg.Chain.Steps, 3)
		assert.Equal(t, "step1", cfg.Chain.Steps[0].Name)
		assert.Equal(t, "file.dat", cfg.Chain.Steps[1].Request.DownloadTo)
		assert.Equal(t, "data.bin", cfg.Chain.Steps[2].Request.UploadBodyFrom)
		require.NotNil(t, cfg.Chain.Output)
		assert.Equal(t, "{{.outfile}}", cfg.Chain.Output.File)
		assert.Equal(t, "data_id", cfg.Chain.Output.Var)
	})

	t.Run("Config with Defaults Applied", func(t *testing.T) {
		minimalYAML := `
apis:
  defaulted:
    base_url: http://default.test
    endpoints:
      ep1: { path: / }
`
		filePath := createTempConfigFile(t, minimalYAML)
		cfg, err := LoadConfig(filePath)
		require.NoError(t, err)
		require.NotNil(t, cfg)
		assert.Equal(t, 1, cfg.Retry.MaxAttempts)
		assert.Equal(t, 1, cfg.Retry.Backoff)
		assert.Equal(t, "info", cfg.Logging.Level)
		assert.Contains(t, cfg.APIs, "defaulted")
	})
}

// TestLoadConfig_ErrorCases tests scenarios where loading itself fails (file issues, parsing). (from original)
func TestLoadConfig_ErrorCases(t *testing.T) {
	t.Run("File Not Found", func(t *testing.T) {
		_, err := LoadConfig("nonexistent_config_file_12345.yaml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read config file")
	})

	t.Run("Invalid YAML Syntax", func(t *testing.T) {
		invalidYAML := `
retry: {max_attempts: 1, backoff_seconds: 1}
logging: {level: info}
apis:
  test: { base_url: "http://a.com", endpoints: { ep1: {path: /p}} } } # Extra brace
`
		filePath := createTempConfigFile(t, invalidYAML)
		_, err := LoadConfig(filePath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse YAML")
		assert.Contains(t, err.Error(), "did not find expected key") // Updated expected error msg
	})

	t.Run("Empty File", func(t *testing.T) {
		filePath := createTempConfigFile(t, "")
		_, err := LoadConfig(filePath)
		require.Error(t, err, "Empty file should result in validation error")
		assert.Contains(t, err.Error(), "Config.APIs: at least one API definition is required")
		assert.NotContains(t, err.Error(), "Config.Logging.Level: is required") // Verify default applied
	})
}

// TestLoadConfig_ValidationErrors tests errors caught by the manual validation logic.
func TestLoadConfig_ValidationErrors(t *testing.T) {
	// Base valid structure for modification in tests
	baseValid := `
retry:
  max_attempts: 1
  backoff_seconds: 1
logging:
  level: info
apis:
  testapi:
    base_url: http://a.com
    endpoints:
      ep1:
        path: /p
`
	// --- Original Validation Tests (kept from original file) ---
	t.Run("Missing Required Top-Level Keys", func(t *testing.T) {
		yaml := `apis: {}` // Retry/Logging are defaulted, APIs is the key missing content here
		filePath := createTempConfigFile(t, yaml)
		_, err := LoadConfig(filePath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Config.APIs: at least one API definition is required")
		assert.NotContains(t, err.Error(), "Config.Logging.Level")
	})

	t.Run("Invalid API Structure", func(t *testing.T) {
		// Fixed: Use valid YAML syntax
		yaml := `
retry: { max_attempts: 1, backoff_seconds: 1 }
logging: { level: info }
apis:
  test: # Missing base_url
    endpoints: { ep1: { path: /p }}
`
		filePath := createTempConfigFile(t, yaml)
		_, err := LoadConfig(filePath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Config.APIs[test].BaseURL: is required")
	})

	t.Run("Invalid Endpoint Structure", func(t *testing.T) {
		// Fixed: Use valid YAML syntax
		yaml := `
retry: { max_attempts: 1, backoff_seconds: 1 }
logging: { level: info }
apis:
  test:
    base_url: http://a.com
    endpoints:
      ep1: {} # Missing path
`
		filePath := createTempConfigFile(t, yaml)
		_, err := LoadConfig(filePath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Config.APIs[test].Endpoints[ep1].Path: is required")
	})

	t.Run("Invalid URL", func(t *testing.T) {
		// Fixed: Use valid YAML syntax
		yaml := `
retry: { max_attempts: 1, backoff_seconds: 1 }
logging: { level: info }
apis:
  test:
    base_url: "htp:/invalid" # Invalid scheme
    endpoints: { ep1: { path: /p }}
`
		filePath := createTempConfigFile(t, yaml)
		_, err := LoadConfig(filePath)
		require.Error(t, err)
		// FIX: Adjust assertion to match the simpler error message
		assert.Contains(t, err.Error(), `invalid URL scheme 'htp', must be http or https`)
	})

	t.Run("Invalid Log Level", func(t *testing.T) {
		// Fixed: Use proper YAML replacement
		yaml := strings.Replace(baseValid, "level: info", "level: trace", 1)
		filePath := createTempConfigFile(t, yaml)
		_, err := LoadConfig(filePath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid log level 'trace'")
	})

	t.Run("Invalid Chain Step Reference API", func(t *testing.T) {
		yaml := baseValid + `
chain:
  steps:
    - request: { api: api2, endpoint: ep1 } # api2 not defined
`
		filePath := createTempConfigFile(t, yaml)
		_, err := LoadConfig(filePath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "references API 'api2' which is not defined")
	})

	t.Run("Invalid Chain Step Reference Endpoint", func(t *testing.T) {
		yaml := baseValid + `
chain:
  steps:
    - request: { api: testapi, endpoint: non_existent_ep } # endpoint not defined
`
		filePath := createTempConfigFile(t, yaml)
		_, err := LoadConfig(filePath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "references Endpoint 'non_existent_ep' which is not defined in API 'testapi'")
	})

	t.Run("Invalid Pagination Config", func(t *testing.T) {
		// Fixed: Correctly modify baseValid YAML
		yaml := strings.Replace(baseValid, "path: /p", `
        path: /p
        pagination: { type: offset, offset_param: o } # Missing limit
`, 1)
		filePath := createTempConfigFile(t, yaml)
		_, err := LoadConfig(filePath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Pagination.Limit: must be positive for type 'offset'")
	})

	// --- NEW Validation Tests for File Handling ---
	t.Run("Chain Request Body Mutual Exclusivity - Data vs Upload", func(t *testing.T) {
		yaml := baseValid + `
chain:
  steps:
    - request: { api: testapi, endpoint: ep1, data: 'x', upload_body_from: y }
`
		filePath := createTempConfigFile(t, yaml)
		_, err := LoadConfig(filePath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only one of 'data', 'upload_body_from'") // Check specific combination text
	})

	t.Run("Chain Request Body Mutual Exclusivity - Upload vs Multipart", func(t *testing.T) {
		yaml := baseValid + `
chain:
  steps:
    - request: { api: testapi, endpoint: ep1, upload_body_from: y, form_data: {f:v} }
`
		filePath := createTempConfigFile(t, yaml)
		_, err := LoadConfig(filePath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only one of 'upload_body_from', 'form_data'/'file_fields'")
	})

	t.Run("Chain Request Body Mutual Exclusivity - Data vs Multipart Files", func(t *testing.T) {
		yaml := baseValid + `
chain:
  steps:
    - request: { api: testapi, endpoint: ep1, data: x, file_fields: {f:p} }
`
		filePath := createTempConfigFile(t, yaml)
		_, err := LoadConfig(filePath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only one of 'data', 'form_data'/'file_fields'")
	})

	t.Run("Chain Request Body Mutual Exclusivity - All Three", func(t *testing.T) {
		yaml := baseValid + `
chain:
  steps:
    - request: { api: testapi, endpoint: ep1, data: 'x', upload_body_from: y, form_data: {f:v} }
`
		filePath := createTempConfigFile(t, yaml)
		_, err := LoadConfig(filePath)
		require.Error(t, err)
		// This specific check might just show the first pair depending on implementation order
		assert.Contains(t, err.Error(), "only one of")
	})

	t.Run("Chain Request Download vs Body Extract Conflict", func(t *testing.T) {
		yaml := baseValid + `
chain:
  steps:
    - request: { api: testapi, endpoint: ep1, download_to: z }
      extract: { body_content: . } # Body extraction
`
		filePath := createTempConfigFile(t, yaml)
		_, err := LoadConfig(filePath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot use 'download_to' and extract data from the response body simultaneously")
	})

	t.Run("Chain Request Download with Only Header Extract (Valid)", func(t *testing.T) {
		// Fixed: This should now pass validation
		yaml := baseValid + `
chain:
  steps:
    - request: { api: testapi, endpoint: ep1, download_to: z }
      extract: { request_id: "header:X-Request-ID:(.*)" } # Header extraction ONLY
`
		filePath := createTempConfigFile(t, yaml)
		_, err := LoadConfig(filePath)
		require.NoError(t, err) // Expect NO error
	})

	t.Run("Chain Request Upload with GET (Validation Error)", func(t *testing.T) {
		yaml := baseValid + `
chain:
  steps:
    - request: { api: testapi, endpoint: ep1, method: GET, upload_body_from: /f }
`
		filePath := createTempConfigFile(t, yaml)
		_, err := LoadConfig(filePath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "'upload_body_from' is typically used with methods like POST/PUT, not GET")
	})

	t.Run("Chain Request Multipart with GET (Validation Error)", func(t *testing.T) {
		yaml := baseValid + `
chain:
  steps:
    - request: { api: testapi, endpoint: ep1, method: GET, form_data: {f:v} }
`
		filePath := createTempConfigFile(t, yaml)
		_, err := LoadConfig(filePath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "'form_data'/'file_fields' (multipart) are typically used with POST/PUT/PATCH, not 'GET'")
	})

	t.Run("Chain Request Download with POST (Validation Error)", func(t *testing.T) {
		yaml := baseValid + `
chain:
  steps:
    - request: { api: testapi, endpoint: ep1, method: POST, download_to: /f }
`
		filePath := createTempConfigFile(t, yaml)
		_, err := LoadConfig(filePath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "'download_to' is typically used with GET, not 'POST'")
	})
}