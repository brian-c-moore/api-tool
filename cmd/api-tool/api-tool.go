package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
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
		Default     string            `yaml:"default"`
		Credentials map[string]string `yaml:"credentials"`
	} `yaml:"auth"`
	Logging struct {
		Level string `yaml:"level"`
	} `yaml:"logging"`
	APIs  map[string]APIConfig `yaml:"apis"`
	Chain *ChainConfig         `yaml:"chain,omitempty"`
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
	Path       string           `yaml:"path"`
	Method     string           `yaml:"method"`
	Pagination PaginationConfig `yaml:"pagination"`
}

// PaginationConfig holds pagination settings, including new fields for offset pagination.
type PaginationConfig struct {
	Type        string `yaml:"type"`                   // "none", "cursor", "offset"
	Param       string `yaml:"param"`                  // legacy offset param
	Limit       int    `yaml:"limit"`                  // legacy limit
	NextField   string `yaml:"next_field"`             // cursor-based next link
	OffsetParam string `yaml:"offset_param,omitempty"` // name of offset parameter
	LimitParam  string `yaml:"limit_param,omitempty"`  // name of limit parameter
	TotalField  string `yaml:"total_field,omitempty"`  // field for total records
}

// XMLResponse is used to parse XML responses.
type XMLResponse struct {
	XMLName xml.Name `yaml:"response"`
	Content string   `yaml:",innerxml"`
}

// ChainConfig defines a multi-step workflow.
type ChainConfig struct {
	Variables map[string]string `yaml:"variables"`
	Steps     []ChainStep       `yaml:"steps"`
	Output    *ChainOutput      `yaml:"output,omitempty"`
}

// ChainOutput defines how to write a variable to a file at the end of chain.
type ChainOutput struct {
	File string `yaml:"file"`
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
	API      string            `yaml:"api"`
	Endpoint string            `yaml:"endpoint"`
	Method   string            `yaml:"method"`
	Data     string            `yaml:"data,omitempty"`
	Headers  map[string]string `yaml:"headers,omitempty"`
}

// ChainFilter defines a local jq filtering step.
type ChainFilter struct {
	Input string `yaml:"input"`
	Jq    string `yaml:"jq"`
}

// CLI flags
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

	if *chainMode && config.Chain != nil {
		if err := runChain(config); err != nil {
			log.Fatalf("Chain execution failed: %v", err)
		}
		return
	}

	if *apiName == "" || *endpoint == "" {
		fmt.Fprintln(os.Stderr, "Error: -api and -endpoint are required in single request mode.")
		flag.Usage()
		os.Exit(1)
	}

	// Single-request logic
	apiConf, ok := config.APIs[*apiName]
	if !ok {
		log.Fatalf("API '%s' not found", *apiName)
	}
	endpointConf, ok := apiConf.Endpoints[*endpoint]
	if !ok {
		log.Fatalf("Endpoint '%s' not found in API '%s'", *endpoint, *apiName)
	}

	// figure out method
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

	// create client
	var client *http.Client
	if apiConf.TlsSkipVerify {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		client = &http.Client{Transport: tr}
		logMessage("TLS verification disabled for API '"+*apiName+"'", "info")
	} else {
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
	}
	if apiConf.CookieJar {
		jar, err := cookiejar.New(nil)
		if err != nil {
			log.Fatalf("Failed to create cookie jar: %v", err)
		}
		client.Jar = jar
		logMessage("Cookie jar enabled for API '"+*apiName+"'", "info")
	}

	logMessage(fmt.Sprintf("Sending request: %s %s", req.Method, req.URL.String()), "debug")
	logMessage(fmt.Sprintf("Headers: %v", req.Header), "debug")
	if len(payload) > 0 {
		logMessage(fmt.Sprintf("Payload: %s", payloadStr), "debug")
	}

	// do single request
	resp, body, err := executeRequestWithRetry(client, req, effectiveAuthType, config)
	if err != nil {
		log.Fatalf("Final request failed: %v", err)
	}
	logMessage(fmt.Sprintf("Response status: %d", resp.StatusCode), "debug")
	logMessage(fmt.Sprintf("Response headers: %v", resp.Header), "debug")
	logMessage("Response body snippet: "+snippet(body), "debug")

	// Print the first page conditionally
	if logLevel >= 2 { // debug
		fmt.Println(string(body))
	} else {
		logMessage("Large first-page body omitted at info level. Use -loglevel=debug to see it.", "info")
	}

	// handle pagination
	switch strings.ToLower(endpointConf.Pagination.Type) {
	case "cursor", "offset":
		pages := handlePagination(client, req, endpointConf, body, config, effectiveAuthType)
		if pages != "" {
			if logLevel >= 2 {
				fmt.Println(pages)
			} else {
				logMessage("Subsequent paginated data omitted at info level. Use -loglevel=debug to see it.", "info")
			}
		}
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
	levels := map[string]int{"none": 0, "info": 1, "debug": 2}
	if lvl, ok := levels[strings.ToLower(level)]; ok && lvl <= logLevel {
		log.Println(message)
	}
}

// setAuthHeaders applies authentication headers
func setAuthHeaders(req *http.Request, effectiveAuthType string, config Config) {
	switch effectiveAuthType {
	case "none":
		return
	case "api_key":
		key, ok := config.Auth.Credentials["api_key"]
		if !ok {
			log.Fatal("API key not found in credentials")
		}
		req.Header.Set("Authorization", "Bearer "+os.ExpandEnv(key))
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
		// handled below in the request logic
	case "oauth2":
		// handled in main for single request
	default:
		log.Fatalf("Unsupported auth type: %s", effectiveAuthType)
	}
}

// executeRequestWithRetry ...
func executeRequestWithRetry(client *http.Client, req *http.Request, effectiveAuthType string, config Config) (*http.Response, []byte, error) {
	attempts := 0
	maxRetries := config.Retry.MaxAttempts
	backoffTime := config.Retry.Backoff

	for {
		if req.GetBody != nil && req.Body != nil {
			newBody, err := req.GetBody()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to reset request body: %v", err)
			}
			req.Body = newBody
		}

		logMessage(fmt.Sprintf("Attempt %d: %s %s", attempts+1, req.Method, req.URL.String()), "debug")

		var resp *http.Response
		var err error
		if effectiveAuthType == "digest" {
			username := config.Auth.Credentials["username"]
			password := config.Auth.Credentials["password"]
			var bodyStr string
			if req.GetBody != nil {
				b, _ := req.GetBody()
				bodyBytes, _ := ioutil.ReadAll(b)
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
			body, rdErr := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if rdErr != nil {
				return nil, nil, fmt.Errorf("failed to read response body: %v", rdErr)
			}

			logMessage(fmt.Sprintf("Response status: %d", resp.StatusCode), "debug")
			logMessage(fmt.Sprintf("Response headers: %v", resp.Header), "debug")

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
				return resp, body, nil
			}
			err = fmt.Errorf("server error: %d", resp.StatusCode)
		}

		attempts++
		if attempts >= maxRetries {
			return nil, nil, fmt.Errorf("max retry attempts reached: %v", err)
		}
		time.Sleep(time.Duration(backoffTime) * time.Second)
	}
}

// handlePagination handles both cursor- and offset-based pagination.
// For offset-based responses that include a "results" array,
// it merges all pages into one JSON object.
func handlePagination(client *http.Client, originalReq *http.Request, endpointConfig EndpointConfig,
	initialBody []byte, config Config, effectiveAuthType string) string {

	pagType := strings.ToLower(endpointConfig.Pagination.Type)
	switch pagType {

	case "cursor":
		// Cursor-based pagination: include the initial page, then loop.
		var allPages strings.Builder
		allPages.Write(initialBody)

		var jsonResponse map[string]interface{}
		if err := json.Unmarshal(initialBody, &jsonResponse); err != nil {
			logMessage(fmt.Sprintf("Failed to parse JSON (cursor-based): %v", err), "info")
			return ""
		}
		nextURL, ok := jsonResponse[endpointConfig.Pagination.NextField].(string)
		for ok && nextURL != "" {
			logMessage(fmt.Sprintf("Cursor next URL: %s", nextURL), "debug")
			parsedURL, err := url.Parse(nextURL)
			if err != nil {
				logMessage(fmt.Sprintf("Failed to parse next URL '%s': %v", nextURL, err), "info")
				break
			}
			req, err := http.NewRequest("GET", parsedURL.String(), nil)
			if err != nil {
				log.Fatalf("Failed to create pagination request: %v", err)
			}
			req.Header = originalReq.Header.Clone()
			_, pageBody, err := executeRequestWithRetry(client, req, effectiveAuthType, config)
			if err != nil {
				log.Fatalf("Cursor pagination request failed: %v", err)
			}
			allPages.Write(pageBody)
			// Update nextURL from the new page
			jsonResponse = map[string]interface{}{}
			if err := json.Unmarshal(pageBody, &jsonResponse); err != nil {
				logMessage(fmt.Sprintf("Failed to parse JSON (cursor next page): %v", err), "info")
				break
			}
			nextURL, ok = jsonResponse[endpointConfig.Pagination.NextField].(string)
		}
		return allPages.String()

	case "offset":
		// Offset-based pagination.
		logMessage("handlePagination initialBody: "+snippet(initialBody), "info")
		pg := endpointConfig.Pagination

		// Determine parameter names and page size.
		offsetParam := pg.OffsetParam
		if offsetParam == "" {
			offsetParam = pg.Param
			if offsetParam == "" {
				offsetParam = "offset"
			}
		}
		limitParam := pg.LimitParam
		if limitParam == "" {
			limitParam = "limit"
		}
		limit := pg.Limit
		if limit <= 0 {
			limit = 100
		}
		totalField := pg.TotalField
		if totalField == "" {
			totalField = "totalRecords"
		}

		// When pg.Param equals "in_query", pagination parameters are sent inside the JSON's "query" subobject.
		paginationInQuery := (strings.ToLower(pg.Param) == "in_query")

		// Parse the initial JSON response.
		var topLevel map[string]interface{}
		if err := json.Unmarshal(initialBody, &topLevel); err != nil {
			logMessage(fmt.Sprintf("Failed to parse JSON (offset-based): %v", err), "info")
			return ""
		}
		var base map[string]interface{}
		if respObj, ok := topLevel["response"].(map[string]interface{}); ok {
			base = respObj
		} else {
			base = topLevel
		}

		// Get the total records count.
		var totalCount int
		if raw, ok := base[totalField]; ok {
			switch val := raw.(type) {
			case float64:
				totalCount = int(val)
			case string:
				n, _ := strconv.Atoi(val)
				totalCount = n
			}
		}

		// Determine how many records were returned in the initial page.
		var retrieved int
		if rr, ok := base["returnedRecords"].(float64); ok {
			retrieved = int(rr)
		} else if rrStr, ok := base["returnedRecords"].(string); ok {
			n, _ := strconv.Atoi(rrStr)
			retrieved = n
		} else if res, ok := base["results"].([]interface{}); ok {
			retrieved = len(res)
		} else {
			retrieved = limit
		}

		logMessage(fmt.Sprintf("Offset pagination: totalRecords=%d, firstPageRecords=%d", totalCount, retrieved), "info")
		// If all records were returned in the first page, no further action is needed.
		if totalCount <= retrieved {
			return string(initialBody)
		}

		// Initialize the merged results with the initial page's results.
		var mergedResults []interface{}
		if res, ok := base["results"].([]interface{}); ok {
			mergedResults = append(mergedResults, res...)
		} else {
			mergedResults = []interface{}{}
		}

		// Loop to retrieve remaining pages.
		currOffset := retrieved
		for currOffset < totalCount {
			logMessage(fmt.Sprintf("Offset pagination iteration: currOffset=%d of %d (limit=%d)", currOffset, totalCount, limit), "info")
			newReq, err := copyRequest(originalReq)
			if err != nil {
				logMessage("Failed to copy request for offset pagination: "+err.Error(), "info")
				break
			}

			// Calculate the new page offsets.
			startVal := currOffset
			endVal := currOffset + limit
			logMessage(fmt.Sprintf("Offset pagination: %s=%d, %s=%d", offsetParam, startVal, limitParam, endVal), "debug")

			if strings.ToUpper(newReq.Method) == "GET" {
				// For GET, add pagination parameters to the query string.
				q := newReq.URL.Query()
				q.Set(offsetParam, strconv.Itoa(startVal))
				q.Set(limitParam, strconv.Itoa(endVal))
				newReq.URL.RawQuery = q.Encode()
			} else {
				// For non-GET requests, update the JSON body.
				bodyBytes, _ := ioutil.ReadAll(newReq.Body)
				newReq.Body.Close()
				var reqJSON map[string]interface{}
				_ = json.Unmarshal(bodyBytes, &reqJSON)
				if reqJSON == nil {
					reqJSON = make(map[string]interface{})
				}
				if paginationInQuery {
					sub, _ := reqJSON["query"].(map[string]interface{})
					if sub == nil {
						sub = make(map[string]interface{})
					}
					sub[offsetParam] = startVal
					sub[limitParam] = endVal
					reqJSON["query"] = sub
				} else {
					reqJSON[offsetParam] = startVal
					reqJSON[limitParam] = endVal
				}
				updated, _ := json.Marshal(reqJSON)
				newReq.Body = ioutil.NopCloser(bytes.NewReader(updated))
				newReq.ContentLength = int64(len(updated))
				newReq.GetBody = func() (io.ReadCloser, error) {
					return ioutil.NopCloser(bytes.NewReader(updated)), nil
				}
			}

			_, pageBody, err := executeRequestWithRetry(client, newReq, effectiveAuthType, config)
			if err != nil {
				log.Fatalf("Offset pagination request failed: %v", err)
			}

			// Parse the new page's JSON.
			var newJSON map[string]interface{}
			if err := json.Unmarshal(pageBody, &newJSON); err != nil {
				logMessage(fmt.Sprintf("Failed to parse JSON in offset paging: %v", err), "info")
				break
			}
			var newRespObj map[string]interface{}
			if sub, ok := newJSON["response"].(map[string]interface{}); ok {
				newRespObj = sub
			} else {
				newRespObj = newJSON
			}
			// Append the results from this page.
			if res, ok := newRespObj["results"].([]interface{}); ok {
				mergedResults = append(mergedResults, res...)
			}

			// Update totalCount if the new response provides it.
			if raw2, ok := newRespObj[totalField]; ok {
				switch val2 := raw2.(type) {
				case float64:
					totalCount = int(val2)
				case string:
					n2, _ := strconv.Atoi(val2)
					if n2 > 0 {
						totalCount = n2
					}
				}
			}

			// Determine how many records were returned on this page.
			var newRetrieved int
			if rr, ok := newRespObj["returnedRecords"].(float64); ok {
				newRetrieved = int(rr)
			} else if rrStr, ok := newRespObj["returnedRecords"].(string); ok {
				n, _ := strconv.Atoi(rrStr)
				if n > 0 {
					newRetrieved = n
				}
			} else if res, ok := newRespObj["results"].([]interface{}); ok {
				newRetrieved = len(res)
			} else {
				newRetrieved = limit
			}
			if newRetrieved == 0 {
				logMessage("No more records returned; pagination stopping.", "info")
				break
			}
			currOffset += newRetrieved
			if currOffset >= totalCount {
				logMessage(fmt.Sprintf("Reached or exceeded total (%d); pagination stopping.", totalCount), "info")
				break
			}
		}

		// Merge the complete results back into the response.
		base["results"] = mergedResults
		base["returnedRecords"] = len(mergedResults)
		base["endOffset"] = strconv.Itoa(len(mergedResults))
		if _, exists := topLevel["response"]; exists {
			topLevel["response"] = base
		} else {
			topLevel = base
		}
		finalData, err := json.Marshal(topLevel)
		if err != nil {
			logMessage(fmt.Sprintf("Failed to marshal final merged JSON: %v", err), "info")
			return ""
		}
		return string(finalData)

	default:
		// If no pagination type is specified, return the initial body.
		return string(initialBody)
	}
}

func copyRequest(req *http.Request) (*http.Request, error) {
	newReq := req.Clone(req.Context())
	newReq.Method = req.Method
	newReq.URL = &url.URL{}
	*newReq.URL = *req.URL
	newReq.Header = req.Header.Clone()

	if req.Body != nil && req.GetBody != nil {
		bCopy, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		newReq.Body = bCopy
	}
	return newReq, nil
}

func logCookieJar(jar http.CookieJar, urlStr string) {
	u, err := url.Parse(urlStr)
	if err != nil {
		logMessage("Error parsing URL for cookie jar: "+err.Error(), "debug")
		return
	}
	cookies := jar.Cookies(u)
	logMessage(fmt.Sprintf("Cookie jar for %s: %v", urlStr, cookies), "debug")
}

// snippet returns a shortened version of the response for debug logging.
func snippet(b []byte) string {
	s := string(b)
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}

// extractHeader extracts a header value using a regex from the response.
// Expected format: "header:HeaderName:regex"
func extractHeader(resp *http.Response, extractionExpr string) (string, error) {
	parts := strings.SplitN(extractionExpr, ":", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid header extraction expression: %s", extractionExpr)
	}
	headerName := parts[1]
	regexPattern := parts[2]
	headerValue := resp.Header.Get(headerName)
	if headerValue == "" {
		return "", fmt.Errorf("header %s not found", headerName)
	}
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return "", fmt.Errorf("invalid regex pattern: %v", err)
	}
	matches := re.FindStringSubmatch(headerValue)
	if len(matches) < 2 {
		return "", fmt.Errorf("failed to extract header %s using pattern %s", headerName, regexPattern)
	}
	return matches[1], nil
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

// runChain handles chain steps
func runChain(config Config) error {
	state := make(map[string]string)
	for k, v := range config.Chain.Variables {
		state[k] = v
	}

	persistentJar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("failed to create persistent cookie jar: %v", err)
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
			endpointConf, ok := apiConf.Endpoints[step.Request.Endpoint]
			if !ok {
				return fmt.Errorf("Endpoint '%s' not found in API '%s'", step.Request.Endpoint, step.Request.API)
			}

			tmplEP, err := template.New("endpoint").Parse(apiConf.BaseURL + endpointConf.Path)
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
				method = endpointConf.Method
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

			effectiveAuthType := strings.ToLower(apiConf.AuthType)
			if effectiveAuthType == "" {
				effectiveAuthType = strings.ToLower(config.Auth.Default)
			}
			setAuthHeaders(req, effectiveAuthType, config)

			var client *http.Client
			if apiConf.TlsSkipVerify {
				tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
				client = &http.Client{Transport: tr}
				logMessage("TLS verification disabled for API '"+step.Request.API+"'", "info")
			} else {
				client = &http.Client{}
			}
			if apiConf.CookieJar {
				client.Jar = persistentJar
				logMessage("Cookie jar enabled for API '"+step.Request.API+"'", "info")
			}

			logMessage(fmt.Sprintf("Step '%s': sending request %s %s", step.Name, req.Method, req.URL.String()), "debug")
			resp, body, err := executeRequestWithRetry(client, req, effectiveAuthType, config)
			if err != nil {
				return fmt.Errorf("error in step '%s': %v", step.Name, err)
			}
			logMessage(fmt.Sprintf("Step '%s': response body snippet: %s", step.Name, snippet(body)), "debug")

			if client.Jar != nil {
				logCookieJar(client.Jar, apiConf.BaseURL)
			}

			// gather multi-page data
			var allData string
			switch strings.ToLower(endpointConf.Pagination.Type) {
			case "cursor", "offset":
				restPages := handlePagination(client, req, endpointConf, body, config, effectiveAuthType)
				if restPages != "" {
					allData = string(body) + restPages
				} else {
					allData = string(body)
				}
			default:
				allData = string(body)
			}

			// extract variables from the multi-page content
			for varName, expr := range step.Extract {
				trimExpr := strings.TrimSpace(expr)
				if strings.HasPrefix(trimExpr, "header:") {
					extracted, err := extractHeader(resp, trimExpr)
					if err != nil {
						return fmt.Errorf("error extracting '%s' in step '%s': %v", varName, step.Name, err)
					}
					state[varName] = extracted
					logMessage(fmt.Sprintf("Step '%s': extracted %s = %s (from header)", step.Name, varName, extracted), "info")
				} else {
					extracted, err := runJqFilter([]byte(allData), expr)
					if err != nil {
						return fmt.Errorf("error extracting '%s' in step '%s': %v", varName, step.Name, err)
					}
					state[varName] = extracted

					// Truncate if extremely large to prevent console spam
					const maxExtractLen = 300
					truncated := extracted
					if len(truncated) > maxExtractLen {
						truncated = truncated[:maxExtractLen] + "..."
					}
					logMessage(fmt.Sprintf("Step '%s': extracted %s = %s", step.Name, varName, truncated), "info")
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

			tmplJq, err := template.New("jqFilter").Parse(step.Filter.Jq)
			if err != nil {
				return fmt.Errorf("parsing jq filter template in step '%s': %v", step.Name, err)
			}
			var jqBuf bytes.Buffer
			if err := tmplJq.Execute(&jqBuf, state); err != nil {
				return fmt.Errorf("executing jq filter template in step '%s': %v", step.Name, err)
			}
			jqFilter := jqBuf.String()

			result, err := runJqFilter([]byte(inputJSON), jqFilter)
			if err != nil {
				return fmt.Errorf("error running filter in step '%s': %v", step.Name, err)
			}
			for varName, val := range step.Extract {
				if strings.Contains(val, "{{result}}") {
					state[varName] = result

					// Also truncate if large
					const maxExtractLen = 300
					truncated := result
					if len(truncated) > maxExtractLen {
						truncated = truncated[:maxExtractLen] + "..."
					}
					logMessage(fmt.Sprintf("Step '%s': filtered result: %s = %s", step.Name, varName, truncated), "info")
				}
			}
		}
	}

	// write chain output file if specified
	if config.Chain.Output != nil && config.Chain.Output.File != "" && config.Chain.Output.Var != "" {
		val, found := state[config.Chain.Output.Var]
		if !found {
			logMessage(fmt.Sprintf("Warning: output var '%s' not found in chain state.", config.Chain.Output.Var), "info")
		} else {
			err := ioutil.WriteFile(config.Chain.Output.File, []byte(val), 0644)
			if err != nil {
				return fmt.Errorf("failed to write output file '%s': %v", config.Chain.Output.File, err)
			}
			logMessage(fmt.Sprintf("Wrote output var '%s' to file '%s'", config.Chain.Output.Var, config.Chain.Output.File), "info")
		}
	}
	return nil
}
