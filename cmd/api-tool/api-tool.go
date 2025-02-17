package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"text/template"
	"time"

	"github.com/Azure/go-ntlmssp"
	digest "github.com/xinsnake/go-http-digest-auth-client"
	"golang.org/x/oauth2/clientcredentials"
	"gopkg.in/yaml.v3"
)

// Config holds the overall configuration including API endpoints and an optional chain workflow.
type Config struct {
	Retry struct {
		MaxAttempts   int   `yaml:"max_attempts"`
		Backoff       int   `yaml:"backoff_seconds"`
		ExcludeErrors []int `yaml:"exclude_errors"`
	} `yaml:"retry"`
	Auth struct {
		Default     string            `yaml:"default"`     // Global default auth type.
		Credentials map[string]string `yaml:"credentials"` // Global credentials.
	} `yaml:"auth"`
	Logging struct {
		Level string `yaml:"level"` // Log verbosity.
	} `yaml:"logging"`
	APIs  map[string]APIConfig `yaml:"apis"`         // API endpoint definitions.
	Chain *ChainConfig       `yaml:"chain,omitempty"` // Optional multi-step workflow.
}

// APIConfig defines a single API's configuration.
type APIConfig struct {
	BaseURL   string                    `yaml:"base_url"`
	AuthType  string                    `yaml:"auth_type"`  // Optional API-specific auth type.
	Endpoints map[string]EndpointConfig `yaml:"endpoints"`  // Defined endpoints.
}

// EndpointConfig defines an endpoint's details.
type EndpointConfig struct {
	Path       string           `yaml:"path"`
	Method     string           `yaml:"method"`
	Pagination PaginationConfig `yaml:"pagination"`
}

// PaginationConfig holds pagination settings.
type PaginationConfig struct {
	Type      string `yaml:"type"`       // "cursor" or "none"
	Param     string `yaml:"param"`      // For offset-based (not implemented)
	Limit     int    `yaml:"limit"`      // For offset-based (not implemented)
	NextField string `yaml:"next_field"` // Field in JSON for next page URL.
}

// XMLResponse is used to parse XML responses.
type XMLResponse struct {
	XMLName xml.Name `xml:"response"`
	Content string   `xml:",innerxml"`
}

// ChainConfig defines a multi-step workflow.
type ChainConfig struct {
	Variables map[string]string `yaml:"variables"` // Initial variables for substitution.
	Steps     []ChainStep       `yaml:"steps"`     // Ordered workflow steps.
}

// ChainStep represents one step in the workflow.
type ChainStep struct {
	Name    string            `yaml:"name"`              // Step name.
	Request *ChainRequest     `yaml:"request,omitempty"` // API request step.
	Filter  *ChainFilter      `yaml:"filter,omitempty"`  // Local filtering step.
	Extract map[string]string `yaml:"extract,omitempty"` // Extraction definitions.
}

// ChainRequest defines an API call in a chain.
type ChainRequest struct {
	API      string            `yaml:"api"`      // Which API configuration to use.
	Endpoint string            `yaml:"endpoint"` // The endpoint key.
	Method   string            `yaml:"method"`   // Optional method override.
	Data     string            `yaml:"data,omitempty"`
	Headers  map[string]string `yaml:"headers,omitempty"`
}

// ChainFilter defines a local jq filtering step.
type ChainFilter struct {
	Input string `yaml:"input"` // JSON input or variable placeholder.
	Jq    string `yaml:"jq"`    // jq expression to run.
}

// CLI flags.
var (
	configFile = flag.String("config", "config.yaml", "YAML configuration file")
	chainMode  = flag.Bool("chain", false, "Run in chain workflow mode")
	apiName    = flag.String("api", "", "API name for single request mode")
	endpoint   = flag.String("endpoint", "", "Endpoint name for single request mode")
	methodFlag = flag.String("method", "", "Override HTTP method")
	headers    = flag.String("headers", "", "Additional headers (Key:Value,...)")
	data       = flag.String("data", "", "JSON payload for POST/PUT")
	verbose    = flag.String("loglevel", "info", "Logging level (none, info, debug)")
	helpFlag   = flag.Bool("help", false, "Show help")
)

var logLevel int

func init() {
	flag.Usage = func() {
		usageText := `Usage:
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
        Logging level (none, info, debug) (default "info")
  -help
        Show help

Examples:
  Single request mode:
    api-tool -config=config.yaml -api myapi -endpoint getdata -loglevel=debug

  Chain workflow mode:
    api-tool -config=chain.yaml --chain -loglevel=debug

`
		fmt.Fprintf(os.Stderr, usageText)
	}
}

func main() {
	flag.Parse()

	if *helpFlag || len(os.Args) == 1 {
		flag.Usage()
		os.Exit(0)
	}

	config := loadConfig(*configFile)
	setLoggingLevel(*verbose)

	// If chain mode is enabled and the chain section exists, run the chain workflow.
	if *chainMode && config.Chain != nil {
		if err := runChain(config); err != nil {
			log.Fatalf("Chain execution failed: %v", err)
		}
		return
	}

	// Single request mode: require both -api and -endpoint.
	if *apiName == "" || *endpoint == "" {
		fmt.Fprintln(os.Stderr, "Error: -api and -endpoint are required in single request mode.")
		flag.Usage()
		os.Exit(1)
	}

	apiConf, ok := config.APIs[*apiName]
	if !ok {
		log.Fatalf("API '%s' not found", *apiName)
	}
	endpointConf, ok := apiConf.Endpoints[*endpoint]
	if !ok {
		log.Fatalf("Endpoint '%s' not found in API '%s'", *endpoint, *apiName)
	}
	httpMethod := *methodFlag
	if httpMethod == "" {
		if endpointConf.Method != "" {
			httpMethod = endpointConf.Method
		} else {
			httpMethod = "GET"
		}
	}
	effectiveAuthType := strings.ToLower(apiConf.AuthType)
	if effectiveAuthType == "" {
		effectiveAuthType = strings.ToLower(config.Auth.Default)
	}
	fullURL := os.ExpandEnv(apiConf.BaseURL) + os.ExpandEnv(endpointConf.Path)
	fullURL = os.ExpandEnv(fullURL)
	payloadStr := os.ExpandEnv(*data)
	payload := []byte(payloadStr)
	var bodyReader io.ReadCloser
	if len(payload) > 0 {
		bodyReader = ioutil.NopCloser(bytes.NewReader(payload))
	}
	req, err := http.NewRequest(httpMethod, fullURL, bodyReader)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}
	if len(payload) > 0 {
		req.GetBody = func() (io.ReadCloser, error) {
			return ioutil.NopCloser(bytes.NewReader(payload)), nil
		}
	}
	if *headers != "" {
		for _, pair := range strings.Split(*headers, ",") {
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) != 2 {
				log.Fatalf("Invalid header format: %s", pair)
			}
			req.Header.Set(strings.TrimSpace(os.ExpandEnv(parts[0])), strings.TrimSpace(os.ExpandEnv(parts[1])))
		}
	}
	setAuthHeaders(req, effectiveAuthType, config)
	logMessage("Authorization header: "+req.Header.Get("Authorization"), "debug")
	var client *http.Client
	switch effectiveAuthType {
	case "ntlm":
		client = &http.Client{Transport: ntlmssp.Negotiator{RoundTripper: http.DefaultTransport}}
	case "oauth2":
		oauthConfig := clientcredentials.Config{
			ClientID:     config.Auth.Credentials["client_id"],
			ClientSecret: config.Auth.Credentials["client_secret"],
			TokenURL:     config.Auth.Credentials["token_url"],
			Scopes:       strings.Split(config.Auth.Credentials["scope"], " "),
		}
		client = oauthConfig.Client(context.Background())
	default:
		client = &http.Client{}
	}
	logMessage(fmt.Sprintf("Sending request: %s %s", req.Method, req.URL.String()), "debug")
	logMessage(fmt.Sprintf("Headers: %v", req.Header), "debug")
	if len(payload) > 0 {
		logMessage(fmt.Sprintf("Payload: %s", payloadStr), "debug")
	}
	body, err := executeRequestWithRetry(client, req, effectiveAuthType, config)
	if err != nil {
		log.Fatalf("Final request failed: %v", err)
	}
	respSnippet := string(body)
	if len(respSnippet) > 200 {
		respSnippet = respSnippet[:200] + "..."
	}
	logMessage("Response body: "+respSnippet, "debug")
	fmt.Println(string(body))
	if strings.ToLower(endpointConf.Pagination.Type) == "cursor" {
		handlePagination(client, req, endpointConf, body, config, effectiveAuthType)
	}
}

// loadConfig reads and unmarshals the YAML configuration.
func loadConfig(filename string) Config {
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}
	var config Config
	if err := yaml.Unmarshal(file, &config); err != nil {
		log.Fatalf("Failed to parse YAML: %v", err)
	}
	return config
}

// setLoggingLevel sets the log verbosity.
func setLoggingLevel(level string) {
	validLevels := map[string]int{"none": 0, "info": 1, "debug": 2}
	lvl, exists := validLevels[strings.ToLower(level)]
	if !exists {
		log.Fatalf("Invalid log level: %s", level)
	}
	logLevel = lvl
}

// logMessage prints a log message if the log level is enabled.
func logMessage(message string, level string) {
	if lvl, ok := map[string]int{"none": 0, "info": 1, "debug": 2}[strings.ToLower(level)]; ok && lvl <= logLevel {
		log.Println(message)
	}
}

// setAuthHeaders applies authentication headers based on the effective auth type.
func setAuthHeaders(req *http.Request, effectiveAuthType string, config Config) {
	switch effectiveAuthType {
	case "none":
	case "api_key":
		if key, ok := config.Auth.Credentials["api_key"]; ok {
			req.Header.Set("Authorization", "Bearer "+os.ExpandEnv(key))
		} else {
			log.Fatal("API key not found in credentials")
		}
	case "bearer":
		token := os.Getenv("API_TOKEN")
		if token == "" {
			log.Fatal("API_TOKEN environment variable is not set")
		}
		req.Header.Set("Authorization", "Bearer "+token)
	case "basic", "ntlm":
		username, ok1 := config.Auth.Credentials["username"]
		password, ok2 := config.Auth.Credentials["password"]
		if !ok1 || !ok2 {
			log.Fatal("Username/password credentials missing")
		}
		req.SetBasicAuth(os.ExpandEnv(username), os.ExpandEnv(password))
	case "digest":
		// Digest is handled by the digest library.
	case "oauth2":
		// OAuth2 is handled by the OAuth2 client.
	default:
		log.Fatalf("Unsupported auth type: %s", effectiveAuthType)
	}
}

// executeRequestWithRetry sends the HTTP request with retry logic.
func executeRequestWithRetry(client *http.Client, req *http.Request, effectiveAuthType string, config Config) ([]byte, error) {
	attempts := 0
	maxRetries := config.Retry.MaxAttempts
	backoffTime := config.Retry.Backoff
	for {
		if req.GetBody != nil && req.Body != nil {
			newBody, err := req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("failed to reset request body: %v", err)
			}
			req.Body = newBody
		}
		logMessage(fmt.Sprintf("Attempt %d: %s %s", attempts+1, req.Method, req.URL.String()), "debug")
		var resp *http.Response
		var err error
		if effectiveAuthType == "digest" {
			username, _ := config.Auth.Credentials["username"]
			password, _ := config.Auth.Credentials["password"]
			var bodyStr string
			if req.GetBody != nil {
				b, err := req.GetBody()
				if err != nil {
					return nil, fmt.Errorf("failed to get body for digest auth: %v", err)
				}
				bodyBytes, err := ioutil.ReadAll(b)
				if err != nil {
					return nil, fmt.Errorf("failed to read body for digest auth: %v", err)
				}
				bodyStr = string(bodyBytes)
			}
			dr := digest.NewRequest(username, password, req.Method, req.URL.String(), bodyStr)
			resp, err = dr.Execute()
		} else {
			resp, err = client.Do(req)
		}
		if err != nil {
			logMessage(fmt.Sprintf("Request error: %v", err), "info")
		} else {
			body, readErr := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				return nil, fmt.Errorf("failed to read response body: %v", readErr)
			}
			retryable := false
			if resp.StatusCode >= 500 && resp.StatusCode < 600 {
				retryable = true
				for _, code := range config.Retry.ExcludeErrors {
					if resp.StatusCode == code {
						retryable = false
						break
					}
				}
			}
			if !retryable {
				ct := resp.Header.Get("Content-Type")
				if strings.Contains(ct, "application/json") {
					logMessage("JSON response received", "debug")
				} else if strings.Contains(ct, "application/xml") || strings.Contains(ct, "text/xml") {
					logMessage("XML response received", "debug")
				} else {
					logMessage(fmt.Sprintf("Response Content-Type: %s", ct), "debug")
				}
				return body, nil
			}
			logMessage(fmt.Sprintf("Server returned status %d. Retrying...", resp.StatusCode), "info")
			err = fmt.Errorf("server error: %d", resp.StatusCode)
		}
		attempts++
		if attempts >= maxRetries {
			return nil, fmt.Errorf("max retry attempts reached: %v", err)
		}
		time.Sleep(time.Duration(backoffTime) * time.Second)
	}
}

// handlePagination processes paginated responses.
func handlePagination(client *http.Client, originalReq *http.Request, endpointConfig EndpointConfig, initialBody []byte, config Config, effectiveAuthType string) {
	var jsonResponse map[string]interface{}
	err := json.Unmarshal(initialBody, &jsonResponse)
	if err != nil {
		logMessage(fmt.Sprintf("Failed to parse JSON response: %v", err), "info")
		return
	}
	nextURL, ok := jsonResponse[endpointConfig.Pagination.NextField].(string)
	for ok && nextURL != "" {
		parsedURL, err := url.Parse(nextURL)
		if err != nil {
			logMessage(fmt.Sprintf("Failed to parse next URL '%s': %v", nextURL, err), "info")
			return
		}
		req, err := http.NewRequest("GET", parsedURL.String(), nil)
		if err != nil {
			log.Fatalf("Failed to create pagination request: %v", err)
		}
		req.Header = originalReq.Header.Clone()
		body, err := executeRequestWithRetry(client, req, effectiveAuthType, config)
		if err != nil {
			log.Fatalf("Pagination request failed: %v", err)
		}
		fmt.Println(string(body))
		err = json.Unmarshal(body, &jsonResponse)
		if err != nil {
			logMessage(fmt.Sprintf("Failed to parse JSON response during pagination: %v", err), "info")
			return
		}
		nextURL, ok = jsonResponse[endpointConfig.Pagination.NextField].(string)
	}
}

// runChain executes the workflow defined in the chain section.
func runChain(config Config) error {
	state := make(map[string]string)
	for k, v := range config.Chain.Variables {
		state[k] = v
	}
	for _, step := range config.Chain.Steps {
		logMessage("Executing step: "+step.Name, "info")
		if step.Request != nil {
			tmpl, err := template.New("data").Parse(step.Request.Data)
			if err != nil {
				return fmt.Errorf("parsing request data template: %v", err)
			}
			var dataBuf bytes.Buffer
			if err := tmpl.Execute(&dataBuf, state); err != nil {
				return fmt.Errorf("executing request data template: %v", err)
			}
			reqHeaders := make(map[string]string)
			for key, val := range step.Request.Headers {
				tmplH, err := template.New("header").Parse(val)
				if err != nil {
					return fmt.Errorf("parsing header template: %v", err)
				}
				var hBuf bytes.Buffer
				if err := tmplH.Execute(&hBuf, state); err != nil {
					return fmt.Errorf("executing header template: %v", err)
				}
				reqHeaders[key] = hBuf.String()
			}
			apiConf, ok := config.APIs[step.Request.API]
			if !ok {
				return fmt.Errorf("API '%s' not found for step '%s'", step.Request.API, step.Name)
			}
			tmplEP, err := template.New("endpoint").Parse(apiConf.BaseURL + apiConf.Endpoints[step.Request.Endpoint].Path)
			if err != nil {
				return fmt.Errorf("parsing endpoint template: %v", err)
			}
			var epBuf bytes.Buffer
			if err := tmplEP.Execute(&epBuf, state); err != nil {
				return fmt.Errorf("executing endpoint template: %v", err)
			}
			fullURL := epBuf.String()
			method := step.Request.Method
			if method == "" {
				method = apiConf.Endpoints[step.Request.Endpoint].Method
			}
			var reqBody io.Reader
			if dataBuf.Len() > 0 {
				reqBody = bytes.NewReader(dataBuf.Bytes())
			}
			req, err := http.NewRequest(method, fullURL, reqBody)
			if err != nil {
				return fmt.Errorf("creating request in step '%s': %v", step.Name, err)
			}
			for key, val := range reqHeaders {
				req.Header.Set(key, val)
			}
			client := &http.Client{}
			logMessage(fmt.Sprintf("Step '%s': sending request %s %s", step.Name, req.Method, req.URL.String()), "debug")
			respBody, err := executeRequestWithRetry(client, req, "none", config)
			if err != nil {
				return fmt.Errorf("error in step '%s': %v", step.Name, err)
			}
			if step.Extract != nil {
				for varName, jqExpr := range step.Extract {
					extracted, err := runJqFilter(respBody, jqExpr)
					if err != nil {
						return fmt.Errorf("error extracting '%s' in step '%s': %v", varName, step.Name, err)
					}
					state[varName] = extracted
					logMessage(fmt.Sprintf("Step '%s': extracted %s = %s", step.Name, varName, extracted), "info")
				}
			}
		} else if step.Filter != nil {
			tmplInput, err := template.New("filterInput").Parse(step.Filter.Input)
			if err != nil {
				return fmt.Errorf("parsing filter input template in step '%s': %v", step.Name, err)
			}
			var inputBuf bytes.Buffer
			if err := tmplInput.Execute(&inputBuf, state); err != nil {
				return fmt.Errorf("executing filter input template in step '%s': %v", step.Name, err)
			}
			inputJSON := inputBuf.String()
			result, err := runJqFilter([]byte(inputJSON), step.Filter.Jq)
			if err != nil {
				return fmt.Errorf("error running filter in step '%s': %v", step.Name, err)
			}
			for varName, val := range step.Extract {
				if strings.Contains(val, "{{result}}") {
					state[varName] = result
					logMessage(fmt.Sprintf("Step '%s': filtered result: %s = %s", step.Name, varName, result), "info")
				}
			}
		}
	}
	logMessage("Final chain state: "+fmt.Sprintf("%v", state), "info")
	return nil
}

// runJqFilter runs a jq expression on the given JSON data.
func runJqFilter(input []byte, jqFilter string) (string, error) {
	cmd := exec.Command("jq", "-r", jqFilter)
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("jq error: %v", err)
	}
	return strings.TrimSpace(string(out)), nil
}
