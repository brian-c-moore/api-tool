package config

import (
	"fmt"
	"net/url"
	"strings"
)

// --- Known values definitions ---
var (
	knownLogLevels            = []string{"none", "error", "warn", "warning", "info", "debug"}
	knownAuthTypes            = []string{"none", "api_key", "basic", "bearer", "digest", "ntlm", "oauth2", ""}
	knownPaginationTypes      = []string{"none", "", "offset", "page", "cursor", "link_header"}
	knownPaginationStrategies = []string{"", "offset", "page"}
	knownParamLocations       = []string{"", "query", "body"}
	knownCursorUsageModes     = []string{"", "query", "body", "url"}
	knownHttpMethods          = []string{"", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
)

// isValidEnumValue checks if a value is present in a list of allowed values.
func isValidEnumValue(value string, allowedValues []string) bool {
	isHTTPMethodsList := len(allowedValues) > 0 && len(knownHttpMethods) > 0 && &allowedValues[0] == &knownHttpMethods[0]
	checkValue := value
	if !isHTTPMethodsList {
		checkValue = strings.ToLower(value)
	}
	for _, allowed := range allowedValues {
		compareAllowed := allowed
		if !isHTTPMethodsList {
			compareAllowed = strings.ToLower(allowed)
		}
		if checkValue == compareAllowed {
			return true
		}
	}
	return false
}

// ValidateConfigManually performs comprehensive validation of the loaded configuration.
func ValidateConfigManually(cfg *Config) error {
	var allErrors []string
	allErrors = append(allErrors, validateRetryConfig("Config.Retry", &cfg.Retry)...)
	allErrors = append(allErrors, validateLoggingConfig("Config.Logging", &cfg.Logging)...)
	allErrors = append(allErrors, validateAuthConfig("Config.Auth", &cfg.Auth)...)
	if len(cfg.APIs) < 1 {
		allErrors = append(allErrors, "- Config.APIs: at least one API definition is required")
	} else {
		for name, apiConf := range cfg.APIs {
			tempAPIConf := apiConf
			if apiErrs := validateAPIConfigManually(fmt.Sprintf("Config.APIs[%s]", name), &tempAPIConf); len(apiErrs) > 0 {
				allErrors = append(allErrors, apiErrs...)
			}
		}
	}
	if cfg.Chain != nil {
		allErrors = append(allErrors, validateChainConfigManually("Config.Chain", cfg)...)
	}
	if len(allErrors) > 0 {
		return fmt.Errorf("configuration validation failed:\n%s", strings.Join(allErrors, "\n"))
	}
	return nil
}

func validateRetryConfig(prefix string, cfg *RetryConfig) []string {
	var errs []string
	if cfg.MaxAttempts < 1 {
		errs = append(errs, fmt.Sprintf("- %s.MaxAttempts: must be at least 1", prefix))
	}
	if cfg.Backoff < 1 {
		errs = append(errs, fmt.Sprintf("- %s.Backoff: must be at least 1 second", prefix))
	}
	return errs
}

func validateLoggingConfig(prefix string, cfg *LoggingConfig) []string {
	var errs []string
	if !isValidEnumValue(cfg.Level, knownLogLevels) {
		errs = append(errs, fmt.Sprintf("- %s.Level: invalid log level '%s', must be one of %v", prefix, cfg.Level, knownLogLevels))
	}
	return errs
}

func validateAuthConfig(prefix string, cfg *AuthConfig) []string {
	var errs []string
	authType := strings.ToLower(cfg.Default)
	if cfg.Default != "" && !isValidEnumValue(authType, knownAuthTypes) {
		errs = append(errs, fmt.Sprintf("- %s.Default: invalid auth type '%s'", prefix, cfg.Default))
	}
	required := map[string][]string{
		"basic":  {"username", "password"},
		"digest": {"username", "password"},
		"ntlm":   {"username", "password"},
		"oauth2": {"client_id", "client_secret", "token_url"},
	}
	if fields, needed := required[authType]; needed {
		if cfg.Credentials == nil {
			errs = append(errs, fmt.Sprintf("- %s.Credentials: map is required for default auth type '%s'", prefix, authType))
		} else {
			for _, field := range fields {
				if v, ok := cfg.Credentials[field]; !ok || v == "" {
					errs = append(errs, fmt.Sprintf("- %s.Credentials: missing or empty required key '%s' for default auth type '%s'", prefix, field, authType))
				}
			}
		}
	}
	if authType == "api_key" {
		if cfg.Credentials == nil || cfg.Credentials["api_key"] == "" {
			errs = append(errs, fmt.Sprintf("- %s.Credentials: missing or empty required key 'api_key' for default auth type 'api_key'", prefix))
		}
	}
	return errs
}

func validateAPIConfigManually(prefix string, cfg *APIConfig) []string {
	var errs []string
	if cfg.BaseURL == "" {
		errs = append(errs, fmt.Sprintf("- %s.BaseURL: is required", prefix))
	} else {
		parsedURL, err := url.ParseRequestURI(cfg.BaseURL)
		if err != nil {
			errs = append(errs, fmt.Sprintf("- %s.BaseURL: invalid URL format: %v", prefix, err))
		} else if scheme := strings.ToLower(parsedURL.Scheme); scheme != "http" && scheme != "https" {
			errs = append(errs, fmt.Sprintf("- %s.BaseURL: invalid URL scheme '%s', must be http or https", prefix, parsedURL.Scheme))
		}
	}
	if cfg.AuthType != "" && !isValidEnumValue(cfg.AuthType, knownAuthTypes) {
		errs = append(errs, fmt.Sprintf("- %s.AuthType: invalid auth type '%s'", prefix, cfg.AuthType))
	}
	if cfg.TimeoutSeconds < 0 {
		errs = append(errs, fmt.Sprintf("- %s.TimeoutSeconds: must be positive", prefix))
	}
	if len(cfg.Endpoints) < 1 {
		errs = append(errs, fmt.Sprintf("- %s.Endpoints: requires at least one endpoint definition", prefix))
	} else {
		for name, epConf := range cfg.Endpoints {
			tempEPConf := epConf
			if epErrs := validateEndpointConfigManually(fmt.Sprintf("%s.Endpoints[%s]", prefix, name), &tempEPConf); len(epErrs) > 0 {
				errs = append(errs, epErrs...)
			}
		}
	}
	return errs
}

func validateEndpointConfigManually(prefix string, cfg *EndpointConfig) []string {
	var errs []string
	if cfg.Path == "" {
		errs = append(errs, fmt.Sprintf("- %s.Path: is required", prefix))
	}
	if cfg.Method != "" && !isValidEnumValue(cfg.Method, knownHttpMethods) {
		errs = append(errs, fmt.Sprintf("- %s.Method: invalid HTTP method '%s'", prefix, cfg.Method))
	}
	if cfg.Pagination != nil {
		if pagErrs := validatePaginationConfigManually(prefix+".Pagination", cfg.Pagination); len(pagErrs) > 0 {
			errs = append(errs, pagErrs...)
		}
	}
	return errs
}

func validatePaginationConfigManually(prefix string, cfg *PaginationConfig) []string {
	var errs []string
	pagType := strings.ToLower(cfg.Type)
	if cfg.Type == "" {
		return errs // None/empty type is valid, no further validation needed
	}
	if !isValidEnumValue(pagType, knownPaginationTypes) {
		errs = append(errs, fmt.Sprintf("- %s.Type: invalid pagination type '%s'", prefix, cfg.Type))
		return errs // Stop further validation if type is invalid
	}
	if cfg.ParamLocation != "" && !isValidEnumValue(cfg.ParamLocation, knownParamLocations) {
		errs = append(errs, fmt.Sprintf("- %s.ParamLocation: invalid location '%s', must be 'query' or 'body'", prefix, cfg.ParamLocation))
	}
	if cfg.MaxPages < 0 {
		errs = append(errs, fmt.Sprintf("- %s.MaxPages: cannot be negative", prefix))
	}

	switch pagType {
	case "offset", "page":
		if cfg.Limit <= 0 {
			errs = append(errs, fmt.Sprintf("- %s.Limit: must be positive for type '%s'", prefix, pagType))
		}
		if cfg.Strategy != "" && !isValidEnumValue(cfg.Strategy, knownPaginationStrategies) {
			errs = append(errs, fmt.Sprintf("- %s.Strategy: invalid strategy '%s', must be 'offset' or 'page'", prefix, cfg.Strategy))
		}
		strategy := strings.ToLower(cfg.Strategy)
		if strategy == "" {
			strategy = pagType // Default strategy to type if not specified
		}

		if strategy == "offset" {
			if cfg.OffsetParam == "" {
				errs = append(errs, fmt.Sprintf("- %s.OffsetParam: is required for offset strategy", prefix))
			}
			if cfg.LimitParam == "" {
				errs = append(errs, fmt.Sprintf("- %s.LimitParam: is required for offset strategy", prefix))
			}
		} else if strategy == "page" {
			if cfg.PageParam == "" {
				errs = append(errs, fmt.Sprintf("- %s.PageParam: is required for page strategy", prefix))
			}
			if cfg.SizeParam == "" {
				// If size_param is missing, limit_param must be provided with a positive limit
				if cfg.LimitParam == "" && cfg.Limit <= 0 {
					errs = append(errs, fmt.Sprintf("- %s: 'size_param' or positive 'limit' with 'limit_param' is required for page strategy", prefix))
				} else if cfg.LimitParam != "" && cfg.Limit <= 0 {
					errs = append(errs, fmt.Sprintf("- %s.Limit: must be positive when 'limit_param' is used for page strategy", prefix))
				}
			}
			if cfg.StartPage < 0 { // Allow 0 for start page (some APIs might use it)
				errs = append(errs, fmt.Sprintf("- %s.StartPage: cannot be negative", prefix))
			}
		}
		// Validation for ForceInitialPaginationParams: Its presence is implicitly validated by the YAML parser ensuring it's a boolean.
		// It's only relevant for offset/page types, and we are inside that case. No further validation needed here.

	case "cursor":
		if cfg.NextField == "" && cfg.NextHeader == "" {
			errs = append(errs, fmt.Sprintf("- %s: one of 'next_field' or 'next_header' is required for cursor pagination", prefix))
		}
		if cfg.NextField != "" && cfg.NextHeader != "" {
			errs = append(errs, fmt.Sprintf("- %s: cannot specify both 'next_field' and 'next_header'", prefix))
		}
		usageMode := strings.ToLower(cfg.CursorUsageMode)
		if usageMode != "" && !isValidEnumValue(usageMode, knownCursorUsageModes) {
			errs = append(errs, fmt.Sprintf("- %s.CursorUsageMode: invalid mode '%s', must be one of %v", prefix, cfg.CursorUsageMode, knownCursorUsageModes))
		}
		if (usageMode == "query" || usageMode == "body") && cfg.CursorParam == "" {
			errs = append(errs, fmt.Sprintf("- %s.CursorParam: is required when CursorUsageMode is 'query' or 'body'", prefix))
		}

	case "link_header":
		// No specific fields required for link_header type itself, besides the base fields already checked.
		if cfg.ForceInitialPaginationParams {
			errs = append(errs, fmt.Sprintf("- %s.ForceInitialPaginationParams: is only applicable for offset/page pagination types", prefix))
		}
	}
	return errs
}

func validateChainFilterManually(prefix string, filter *ChainFilter) []string {
	var errs []string
	if filter.Input == "" {
		errs = append(errs, fmt.Sprintf("- %s.Input: is required", prefix))
	}
	if filter.Jq == "" {
		errs = append(errs, fmt.Sprintf("- %s.Jq: is required", prefix))
	}
	return errs
}

func validateChainOutputManually(prefix string, output *ChainOutput) []string {
	var errs []string
	if output.File == "" {
		errs = append(errs, fmt.Sprintf("- %s.File: is required", prefix))
	}
	if output.Var == "" {
		errs = append(errs, fmt.Sprintf("- %s.Var: is required", prefix))
	}
	return errs
}

func checkMutualExclusivity(prefix string, descriptions []string, options ...bool) []string {
	count := 0
	var present []string
	for i, presentFlag := range options {
		if presentFlag {
			count++
			if i < len(descriptions) {
				present = append(present, descriptions[i])
			} else {
				present = append(present, fmt.Sprintf("option %d", i+1))
			}
		}
	}
	if count > 1 {
		return []string{fmt.Sprintf("- %s: only one of %s can be specified", prefix, strings.Join(present, ", "))}
	}
	return nil
}

func validateChainConfigManually(prefix string, cfg *Config) []string {
	var errs []string
	if len(cfg.Chain.Steps) < 1 {
		errs = append(errs, fmt.Sprintf("- %s.Steps: requires at least one step", prefix))
	}
	for i, step := range cfg.Chain.Steps {
		tempStep := step
		if stepErrs := validateChainStepManually(fmt.Sprintf("%s.Steps[%d]", prefix, i), cfg, &tempStep); len(stepErrs) > 0 {
			errs = append(errs, stepErrs...)
		}
	}
	if cfg.Chain.Output != nil {
		tempOutput := *cfg.Chain.Output
		if outputErrs := validateChainOutputManually(prefix+".Output", &tempOutput); len(outputErrs) > 0 {
			errs = append(errs, outputErrs...)
		}
	}
	return errs
}

func validateChainStepManually(prefix string, cfg *Config, step *ChainStep) []string {
	var errs []string
	hasRequest := step.Request != nil
	hasFilter := step.Filter != nil
	if !hasRequest && !hasFilter {
		errs = append(errs, fmt.Sprintf("- %s: Request or Filter must be defined", prefix))
		return errs
	}
	if hasRequest && hasFilter {
		errs = append(errs, fmt.Sprintf("- %s: Only one of Request or Filter can be defined", prefix))
	}
	if hasRequest {
		if reqErrs := validateChainRequestManually(prefix+".Request", cfg, step.Request, step.Extract); len(reqErrs) > 0 {
			errs = append(errs, reqErrs...)
		}
	}
	if hasFilter {
		tempFilter := *step.Filter
		if filterErrs := validateChainFilterManually(prefix+".Filter", &tempFilter); len(filterErrs) > 0 {
			errs = append(errs, filterErrs...)
		}
	}
	return errs
}

func validateChainRequestManually(prefix string, cfg *Config, req *ChainRequest, extract map[string]string) []string {
	var errs []string
	if req.API == "" {
		errs = append(errs, fmt.Sprintf("- %s.API: is required", prefix))
	}
	if req.Endpoint == "" {
		errs = append(errs, fmt.Sprintf("- %s.Endpoint: is required", prefix))
	}
	if req.Method != "" && !isValidEnumValue(req.Method, knownHttpMethods) {
		errs = append(errs, fmt.Sprintf("- %s.Method: invalid HTTP method '%s'", prefix, req.Method))
	}
	// Validate API/Endpoint references
	if req.API != "" && req.Endpoint != "" {
		if cfg.APIs == nil {
			errs = append(errs, fmt.Sprintf("- %s: Internal Error - Cannot validate API/Endpoint references", prefix)) // Should not happen if top-level validation passed
		} else if apiConf, apiExists := cfg.APIs[req.API]; !apiExists {
			errs = append(errs, fmt.Sprintf("- %s.API: references API '%s' which is not defined", prefix, req.API))
		} else if _, epExists := apiConf.Endpoints[req.Endpoint]; !epExists {
			errs = append(errs, fmt.Sprintf("- %s.Endpoint: references Endpoint '%s' which is not defined in API '%s'", prefix, req.Endpoint, req.API))
		}
	}
	// Validate mutual exclusivity of body options
	bodyDesc := []string{"'data'", "'upload_body_from'", "'form_data'/'file_fields'"}
	bodyOpts := []bool{req.Data != "", req.UploadBodyFrom != "", (len(req.FormData) > 0 || len(req.FileFields) > 0)}
	errs = append(errs, checkMutualExclusivity(prefix, bodyDesc, bodyOpts...)...)
	// Validate download vs body extraction
	hasDownloadTo := req.DownloadTo != ""
	hasBodyExtraction := false
	for _, expression := range extract { // Range over nil map is safe
		if !strings.HasPrefix(strings.TrimSpace(expression), "header:") {
			hasBodyExtraction = true
			break
		}
	}
	if hasDownloadTo && hasBodyExtraction {
		errs = append(errs, fmt.Sprintf("- %s: cannot use 'download_to' and extract data from the response body simultaneously", prefix))
	}
	// Validate method vs body/download options
	effectiveMethod := req.Method
	if effectiveMethod == "" {
		if apiConf, apiExists := cfg.APIs[req.API]; apiExists {
			if epConf, epExists := apiConf.Endpoints[req.Endpoint]; epExists {
				effectiveMethod = epConf.Method
			}
		}
		if effectiveMethod == "" {
			effectiveMethod = "GET" // Default if not specified anywhere
		}
	}
	if req.UploadBodyFrom != "" && effectiveMethod == "GET" {
		errs = append(errs, fmt.Sprintf("- %s: 'upload_body_from' is typically used with methods like POST/PUT, not GET", prefix))
	}
	isMultipart := len(req.FormData) > 0 || len(req.FileFields) > 0
	if isMultipart && effectiveMethod != "POST" && effectiveMethod != "PUT" && effectiveMethod != "PATCH" {
		errs = append(errs, fmt.Sprintf("- %s: 'form_data'/'file_fields' (multipart) are typically used with POST/PUT/PATCH, not '%s'", prefix, effectiveMethod))
	}
	if hasDownloadTo && effectiveMethod != "GET" {
		errs = append(errs, fmt.Sprintf("- %s: 'download_to' is typically used with GET, not '%s'", prefix, effectiveMethod))
	}
	return errs
}