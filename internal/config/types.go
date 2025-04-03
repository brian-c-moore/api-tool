package config

// Config holds the overall configuration including API endpoints and an optional chain workflow.
type Config struct {
	Retry    RetryConfig          `yaml:"retry"`
	Auth     AuthConfig           `yaml:"auth"`
	Logging  LoggingConfig        `yaml:"logging"`
	APIs     map[string]APIConfig `yaml:"apis"`
	Chain    *ChainConfig         `yaml:"chain,omitempty"`
	FipsMode bool                 `yaml:"fips_mode,omitempty"`
}

// RetryConfig holds settings for retry logic.
type RetryConfig struct {
	MaxAttempts   int   `yaml:"max_attempts"`
	Backoff       int   `yaml:"backoff_seconds"`
	ExcludeErrors []int `yaml:"exclude_errors"`
}

// AuthConfig holds global authentication settings.
type AuthConfig struct {
	Default     string            `yaml:"default"`
	Credentials map[string]string `yaml:"credentials"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level string `yaml:"level"`
}

// APIConfig defines a single API's configuration.
type APIConfig struct {
	BaseURL       string                    `yaml:"base_url"`
	AuthType      string                    `yaml:"auth_type"`
	TlsSkipVerify bool                      `yaml:"tls_skip_verify,omitempty"`
	CookieJar     bool                      `yaml:"cookie_jar,omitempty"`
	Endpoints     map[string]EndpointConfig `yaml:"endpoints"`
}

// EndpointConfig defines an endpoint's details.
type EndpointConfig struct {
	Path       string            `yaml:"path"`
	Method     string            `yaml:"method"`
	Pagination *PaginationConfig `yaml:"pagination,omitempty"`
}

// PaginationConfig holds the flexible pagination settings.
type PaginationConfig struct {
	Type          string `yaml:"type"`
	ParamLocation string `yaml:"param_location,omitempty"`
	BodyPath      string `yaml:"body_path,omitempty"`
	ResultsField  string `yaml:"results_field,omitempty"`
	MaxPages      int    `yaml:"max_pages,omitempty"`

	// Offset/Page Specific Settings
	Strategy    string `yaml:"strategy,omitempty"`
	OffsetParam string `yaml:"offset_param,omitempty"`
	LimitParam  string `yaml:"limit_param,omitempty"`
	PageParam   string `yaml:"page_param,omitempty"`
	SizeParam   string `yaml:"size_param,omitempty"`
	Limit       int    `yaml:"limit,omitempty"`
	StartPage   int    `yaml:"start_page,omitempty"`
	TotalField  string `yaml:"total_field,omitempty"`
	TotalHeader string `yaml:"total_header,omitempty"`

	// Cursor Specific Settings
	NextField       string `yaml:"next_field,omitempty"`
	NextHeader      string `yaml:"next_header,omitempty"`
	CursorUsageMode string `yaml:"cursor_usage_mode,omitempty"`
	CursorParam     string `yaml:"cursor_param,omitempty"`
}

// ChainConfig defines a multi-step workflow.
type ChainConfig struct {
	Variables map[string]string `yaml:"variables"`
	Steps     []ChainStep       `yaml:"steps"`
	Output    *ChainOutput      `yaml:"output,omitempty"`
}

// ChainOutput defines how to write a variable to a file at the end of chain.
type ChainOutput struct {
	File string `yaml:"file"` // Path template/env enabled
	Var  string `yaml:"var"`
}

// ChainStep represents one step in the workflow.
type ChainStep struct {
	Name    string            `yaml:"name"`
	Request *ChainRequest     `yaml:"request,omitempty"`
	Filter  *ChainFilter      `yaml:"filter,omitempty"`
	Extract map[string]string `yaml:"extract,omitempty"`
}

// ChainRequest defines an API call in a chain.
type ChainRequest struct {
	API      string `yaml:"api"`      // Required
	Endpoint string `yaml:"endpoint"` // Required
	Method   string `yaml:"method,omitempty"`

	// Mutually Exclusive Body Options:
	// Only one of the following three groups can be specified per step:
	// 1. data: Use a string (with template support) as the request body.
	// 2. upload_body_from: Use the raw content of a local file as the request body.
	// 3. form_data/file_fields: Build a multipart/form-data request body.
	Data           string            `yaml:"data,omitempty"`             // Option 1: Body as a string (template enabled)
	UploadBodyFrom string            `yaml:"upload_body_from,omitempty"` // Option 2: File path for raw body upload (template/env enabled)
	FormData       map[string]string `yaml:"form_data,omitempty"`        // Option 3a: Key-value pairs for multipart fields (template enabled)
	FileFields     map[string]string `yaml:"file_fields,omitempty"`      // Option 3b: Map form field name -> local file path for multipart files (template/env enabled)

	// Other Fields:
	Headers map[string]string `yaml:"headers,omitempty"` // Existing: Request headers (template enabled)

	// Download Action:
	// If specified, the raw response body will be saved to this file path (template/env enabled).
	// This is mutually exclusive with extracting data from the response *body* using the 'extract' map.
	// Header extraction is still permitted when 'download_to' is used.
	DownloadTo string `yaml:"download_to,omitempty"`
}

// ChainFilter defines a local jq filtering step.
type ChainFilter struct {
	Input string `yaml:"input"`
	Jq    string `yaml:"jq"`
}