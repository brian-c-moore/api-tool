package executor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"api-tool/internal/config"
	"api-tool/internal/logging"

	"github.com/tidwall/gjson"
)

// HandlePagination manages fetching subsequent pages based on the endpoint configuration.
// It retrieves all pages according to the specified pagination strategy and merges the results.
// Returns a single JSON string containing an array of the merged results extracted via `results_field`.
func HandlePagination(
	client *http.Client,
	originalReq *http.Request,
	endpointCfg config.EndpointConfig,
	initialResp *http.Response,
	initialBodyBytes []byte,
	effectiveAuthType string,
	authCreds map[string]string,
	retryCfg config.RetryConfig,
	// cookieJar parameter removed as client handles persistence internally.
	logLevel int,
) (string, error) {

	if endpointCfg.Pagination == nil || endpointCfg.Pagination.Type == "" || endpointCfg.Pagination.Type == "none" {
		return string(initialBodyBytes), nil
	}

	// Work on a copy to apply defaults without modifying the original endpoint config.
	pagCfgCopy := *endpointCfg.Pagination
	pagCfg := &pagCfgCopy // Use pointer for applying defaults.

	pagType := strings.ToLower(pagCfg.Type)
	logging.Logf(logging.Info, "Pagination type '%s' detected. Starting pagination handling...", pagType)

	// Apply defaults and validate the configuration before proceeding.
	applyPaginationDefaults(pagCfg, pagType)
	if err := validatePaginationConfig(pagCfg, pagType); err != nil {
		return string(initialBodyBytes), fmt.Errorf("invalid pagination configuration: %w", err)
	}

	var mergedResultsJSON string
	var err error

	// Dispatch to the appropriate handler, passing the finalized config pointer.
	switch pagType {
	case "offset", "page":
		// Pass pointer pagCfg instead of value *pagCfg
		mergedResultsJSON, err = handleOffsetOrPagePagination(client, originalReq, pagCfg, initialResp, initialBodyBytes, effectiveAuthType, authCreds, retryCfg, logLevel)
	case "cursor":
		// Pass pointer pagCfg instead of value *pagCfg
		mergedResultsJSON, err = handleCursorPagination(client, originalReq, pagCfg, initialResp, initialBodyBytes, effectiveAuthType, authCreds, retryCfg, logLevel)
	case "link_header":
		// Pass pointer pagCfg instead of value *pagCfg (though less critical here as fewer defaults used)
		mergedResultsJSON, err = handleLinkHeaderPagination(client, originalReq, pagCfg, initialResp, initialBodyBytes, effectiveAuthType, authCreds, retryCfg, logLevel)
	default:
		logging.Logf(logging.Warning, "Unsupported pagination type '%s'. Ignoring.", pagCfg.Type)
		return string(initialBodyBytes), nil
	}

	// Handle results, returning partial data if an error occurred mid-pagination.
	if err != nil {
		logging.Logf(logging.Error, "Pagination failed: %v. Returning collected data if any.", err)
		if mergedResultsJSON != "" {
			return mergedResultsJSON, fmt.Errorf("pagination failed partially: %w", err)
		}
		return string(initialBodyBytes), fmt.Errorf("pagination failed: %w", err)
	}

	logging.Logf(logging.Info, "Pagination finished. Returning merged results.")
	return mergedResultsJSON, nil
}

// applyPaginationDefaults sets default values for common pagination parameters.
func applyPaginationDefaults(pagCfg *config.PaginationConfig, pagType string) {
	if pagCfg.ResultsField == "" {
		pagCfg.ResultsField = "results"
	}
	if pagCfg.ParamLocation == "" {
		pagCfg.ParamLocation = "query"
	}
	pagCfg.ParamLocation = strings.ToLower(pagCfg.ParamLocation)

	if pagType == "offset" || pagType == "page" {
		pagCfg.Strategy = strings.ToLower(pagCfg.Strategy)
		if pagCfg.Strategy != "offset" && pagCfg.Strategy != "page" {
			pagCfg.Strategy = "offset"
		} // Default to offset if invalid
		if pagCfg.Strategy == "offset" {
			if pagCfg.OffsetParam == "" {
				pagCfg.OffsetParam = "offset"
			}
			if pagCfg.LimitParam == "" {
				pagCfg.LimitParam = "limit"
			}
		} else { // page strategy
			if pagCfg.PageParam == "" {
				pagCfg.PageParam = "page"
			}
			if pagCfg.SizeParam == "" {
				pagCfg.SizeParam = "size"
			}
			// If LimitParam wasn't set, default it to SizeParam for consistency in helpers
			if pagCfg.LimitParam == "" {
				pagCfg.LimitParam = pagCfg.SizeParam
			}
			if pagCfg.StartPage <= 0 {
				pagCfg.StartPage = 1
			}
		}
	}

	if pagType == "cursor" {
		if pagCfg.CursorUsageMode == "" {
			pagCfg.CursorUsageMode = "query"
		} // Default usage mode
		pagCfg.CursorUsageMode = strings.ToLower(pagCfg.CursorUsageMode)
		if pagCfg.CursorParam == "" {
			pagCfg.CursorParam = "cursor"
		} // Default cursor parameter name
		// Automatically set location to body if cursor usage requires it and not already set.
		if pagCfg.CursorUsageMode == "body" && pagCfg.ParamLocation != "body" {
			pagCfg.ParamLocation = "body"
			logging.Logf(logging.Debug, "Pagination: Automatically setting param_location to 'body' due to cursor_usage_mode 'body'")
		}
	}
}

// validatePaginationConfig checks for configuration errors.
func validatePaginationConfig(pagCfg *config.PaginationConfig, pagType string) error {
	if pagCfg.ParamLocation != "query" && pagCfg.ParamLocation != "body" {
		return fmt.Errorf("invalid param_location: '%s', must be 'query' or 'body'", pagCfg.ParamLocation)
	}
	if pagType == "offset" || pagType == "page" {
		if pagCfg.Limit <= 0 {
			return fmt.Errorf("type '%s' requires a positive 'limit' value", pagType)
		}
	}
	if pagType == "cursor" {
		if pagCfg.NextField == "" && pagCfg.NextHeader == "" {
			return fmt.Errorf("cursor type requires 'next_field' or 'next_header'")
		}
		if pagCfg.NextField != "" && pagCfg.NextHeader != "" {
			return fmt.Errorf("cannot have both 'next_field' and 'next_header'")
		}
		if pagCfg.CursorUsageMode != "query" && pagCfg.CursorUsageMode != "body" && pagCfg.CursorUsageMode != "url" {
			return fmt.Errorf("invalid cursor_usage_mode: '%s', must be 'query', 'body', or 'url'", pagCfg.CursorUsageMode)
		}
	}
	// No validation needed for MaxPages <= 0, as that means unlimited.
	return nil
}

// ========================= Offset / Page =========================
func handleOffsetOrPagePagination(
	client *http.Client, originalReq *http.Request, pagCfg *config.PaginationConfig, // Receive config by pointer
	initialResp *http.Response, initialBodyBytes []byte, effectiveAuthType string,
	authCreds map[string]string, retryCfg config.RetryConfig, logLevel int,
) (string, error) {

	var mergedResults []json.RawMessage
	currentPageNum := pagCfg.StartPage
	// *** FIX: Removed unused currentOffset variable and its calculation ***
	totalRecords := -1 // Initialize totalRecords as unknown
	currentPageBody := initialBodyBytes
	currentPageResp := initialResp
	currentReq := originalReq // Start with the original request

	// pageIndex is 0-based count of *fetched* pages (0 is initial page)
	for pageIndex := 0; ; pageIndex++ {
		// Handle empty body (except for the very first page)
		if len(currentPageBody) == 0 && pageIndex > 0 {
			logging.Logf(logging.Info, "Pagination: Received empty body on page %d. Stopping.", pageIndex+1)
			break
		}

		// Parse current page and extract results
		pageParsed := gjson.ParseBytes(currentPageBody)
		resultsData := pageParsed.Get(pagCfg.ResultsField)
		currentPageItemCount := 0
		if resultsData.Exists() && resultsData.IsArray() {
			items := resultsData.Array()
			currentPageItemCount = len(items)
			for _, item := range items {
				mergedResults = append(mergedResults, json.RawMessage(item.Raw))
			}
			logging.Logf(logging.Debug, "Pagination: Extracted %d items on page %d (index %d). Total so far: %d", currentPageItemCount, pageIndex+1, pageIndex, len(mergedResults))
		} else {
			// Log warning if results field not found or not an array
			if pageIndex == 0 {
				logging.Logf(logging.Warning, "Pagination: Results field '%s' not found or not an array in initial response.", pagCfg.ResultsField)
				// Don't break immediately on first page, maybe it's just an empty list
			} else {
				logging.Logf(logging.Warning, "Pagination: Results field '%s' not found or not an array on page %d (index %d). Stopping.", pagCfg.ResultsField, pageIndex+1, pageIndex)
				break
			}
		}

		// --- Stop Conditions ---
		// 1. Check total records if known
		if totalRecords == -1 { // Only check total once
			totalRecords = getTotalRecords(pageParsed, currentPageResp, pagCfg) // Pass the pointer directly
		}
		if totalRecords != -1 && len(mergedResults) >= totalRecords {
			logging.Logf(logging.Info, "Pagination: Collected items %d >= known total %d. Stopping.", len(mergedResults), totalRecords)
			break
		}
		// 2. Check if fewer items than limit were returned (only reliable after first page if total is unknown)
		if totalRecords == -1 && currentPageItemCount < pagCfg.Limit && pageIndex > 0 {
			logging.Logf(logging.Info, "Pagination: Received %d items < limit %d, and total unknown. Assuming end. Stopping.", currentPageItemCount, pagCfg.Limit)
			break
		}
		// 3. Stop if an empty page of results was received (and wasn't the first page)
		if currentPageItemCount == 0 && pageIndex > 0 {
			logging.Logf(logging.Info, "Pagination: Received 0 items on page %d (index %d). Stopping.", pageIndex+1, pageIndex)
			break
		}

		// --- Check MaxPages BEFORE preparing the next request ---
		// pageIndex is 0 for the first page, 1 for the second, etc.
		// So, if MaxPages is 2, we want to fetch page index 0 and 1, but stop *before* fetching page index 2.
		// The check should be against the *next* page index we are *about* to fetch.
		nextPageIndex := pageIndex + 1
		if pagCfg.MaxPages > 0 && nextPageIndex >= pagCfg.MaxPages {
			logging.Logf(logging.Info, "Pagination: Reached configured max_pages (%d). Stopping.", pagCfg.MaxPages)
			break
		}

		// --- Prepare for Next Page ---
		if pagCfg.Strategy == "page" {
			currentPageNum++ // Increment page number for page strategy
		}
		// For offset strategy, or calculating offset for logging/body mods, use total collected count.
		// *** FIX: Removed assignment to unused currentOffset variable ***
		calculatedOffset := len(mergedResults) // Use a local variable if needed for logging
		logging.Logf(logging.Info, "Pagination: Preparing next page request. Next Offset=%d, Next Page=%d", calculatedOffset, currentPageNum) // Log calculated offset

		// Create the next request based on the *previous* one
		nextReq, err := copyRequest(currentReq)
		if err != nil {
			return marshalResults(mergedResults), fmt.Errorf("failed copy request for next page: %w", err)
		}
		// *** FIX: Use calculatedOffset directly for offsetStr ***
		offsetStr := strconv.Itoa(calculatedOffset)
		limitStr := strconv.Itoa(pagCfg.Limit)
		pageStr := strconv.Itoa(currentPageNum)
		isGetMethod := (nextReq.Method == "GET" || nextReq.Method == "") // Treat empty method as GET

		// Modify the request based on ParamLocation
		if pagCfg.ParamLocation == "query" {
			if !isGetMethod {
				logging.Logf(logging.Warning, "Pagination: param_location is 'query' but method is '%s'. Parameters might not be applied correctly.", nextReq.Method)
			}
			// Pass config pointer to helper
			err = modifyRequestQueryForOffsetPage(nextReq, pagCfg, offsetStr, limitStr, pageStr) // Pass pointer
		} else if pagCfg.ParamLocation == "body" {
			if isGetMethod {
				logging.Logf(logging.Warning, "Pagination: param_location is 'body' but method is 'GET'. Body modification might be ignored by server.")
			}
			// Pass config pointer to helper
			err = modifyRequestBodyForOffsetPage(nextReq, pagCfg, offsetStr, limitStr, pageStr) // Pass pointer
		} else {
			// Should be caught by validation, but log just in case.
			logging.Logf(logging.Warning, "Pagination: Invalid param_location '%s'. Skipping request modification.", pagCfg.ParamLocation)
		}
		if err != nil {
			// Error during request modification (e.g., JSON parsing/path finding)
			return marshalResults(mergedResults), err
		}

		// Execute the next request
		resp, bodyBytes, execErr := ExecuteRequest(client, nextReq, effectiveAuthType, authCreds, retryCfg, logLevel)
		if execErr != nil {
			// *** FIX: Use calculatedOffset in log message ***
			logging.Logf(logging.Error, "Pagination: Failed to fetch page (offset %d / page %d): %v. Stopping.", calculatedOffset, currentPageNum, execErr)
			return marshalResults(mergedResults), execErr // Return partial results and the error
		}
		if resp != nil { // Close the response body even if there was an error reading it later
			resp.Body.Close()
		}
		currentPageBody = bodyBytes
		currentPageResp = resp
		currentReq = nextReq // Update currentReq for the *next* iteration's copyRequest
	}
	return marshalResults(mergedResults), nil
}

// ========================= Cursor =========================
func handleCursorPagination(
	client *http.Client, originalReq *http.Request, pagCfg *config.PaginationConfig, // Receive config by pointer
	initialResp *http.Response, initialBodyBytes []byte, effectiveAuthType string,
	authCreds map[string]string, retryCfg config.RetryConfig, logLevel int,
) (string, error) {

	var mergedResults []json.RawMessage
	currentPageBody := initialBodyBytes
	currentPageResp := initialResp
	currentReq := originalReq // Start with the original request

	// pageIndex is 0-based count of *fetched* pages (0 is initial page)
	for pageIndex := 0; ; pageIndex++ {
		// Handle empty body (except for the very first page)
		if len(currentPageBody) == 0 && pageIndex > 0 {
			logging.Logf(logging.Info, "Pagination (Cursor): Received empty body on page %d (index %d). Stopping.", pageIndex+1, pageIndex)
			break
		}

		// Parse current page and extract results
		pageParsed := gjson.ParseBytes(currentPageBody)
		resultsData := pageParsed.Get(pagCfg.ResultsField)
		currentPageItemCount := 0 // Count items on this page
		if resultsData.Exists() && resultsData.IsArray() {
			items := resultsData.Array()
			currentPageItemCount = len(items)
			for _, item := range items {
				mergedResults = append(mergedResults, json.RawMessage(item.Raw))
			}
			logging.Logf(logging.Debug, "Pagination (Cursor): Extracted %d items on page %d (index %d). Total so far: %d", currentPageItemCount, pageIndex+1, pageIndex, len(mergedResults))
		} else {
			if pageIndex == 0 {
				logging.Logf(logging.Warning, "Pagination (Cursor): Results field '%s' not found or not an array in initial response.", pagCfg.ResultsField)
			} else {
				logging.Logf(logging.Warning, "Pagination (Cursor): Results field '%s' not found or not an array on page %d (index %d). Stopping.", pagCfg.ResultsField, pageIndex+1, pageIndex)
				break
			}
		}

		// --- Stop Condition: Check for next cursor ---
		nextCursor := getNextCursor(pageParsed, currentPageResp, pagCfg) // Pass the pointer directly
		if nextCursor == "" {
			logging.Logf(logging.Info, "Pagination (Cursor): No next cursor found. Stopping.")
			break
		}
		logging.Logf(logging.Debug, "Pagination (Cursor): Found next cursor: %s", nextCursor)

		// --- Check MaxPages BEFORE preparing the next request ---
		nextPageIndex := pageIndex + 1
		if pagCfg.MaxPages > 0 && nextPageIndex >= pagCfg.MaxPages {
			logging.Logf(logging.Info, "Pagination (Cursor): Reached configured max_pages (%d). Stopping.", pagCfg.MaxPages)
			break
		}

		// --- Prepare for Next Page ---
		nextReq, err := copyRequest(currentReq)
		if err != nil {
			return marshalResults(mergedResults), fmt.Errorf("failed copy request for next cursor page: %w", err)
		}

		// Pass config pointer to helper
		err = modifyRequestForCursor(nextReq, currentReq.URL, pagCfg, nextCursor)
		if err != nil {
			return marshalResults(mergedResults), err // Error during request modification
		}

		// Execute the next request
		resp, bodyBytes, execErr := ExecuteRequest(client, nextReq, effectiveAuthType, authCreds, retryCfg, logLevel)
		if execErr != nil {
			logging.Logf(logging.Error, "Pagination (Cursor): Failed to fetch next page using cursor '%s': %v. Stopping.", nextCursor, execErr)
			return marshalResults(mergedResults), execErr // Return partial results and the error
		}
		if resp != nil {
			resp.Body.Close()
		}
		currentPageBody = bodyBytes
		currentPageResp = resp
		currentReq = nextReq // Update currentReq for the *next* iteration's copyRequest
	}
	return marshalResults(mergedResults), nil
}

// ========================= Link Header =========================
func handleLinkHeaderPagination(
	client *http.Client, originalReq *http.Request, pagCfg *config.PaginationConfig, // Receive config by pointer
	initialResp *http.Response, initialBodyBytes []byte, effectiveAuthType string,
	authCreds map[string]string, retryCfg config.RetryConfig, logLevel int,
) (string, error) {

	var mergedResults []json.RawMessage
	currentPageBody := initialBodyBytes
	currentPageResp := initialResp
	currentReq := originalReq // Start with the original request

	// pageIndex is 0-based count of *fetched* pages (0 is initial page)
	for pageIndex := 0; ; pageIndex++ {
		// Handle empty body (except for the very first page)
		if len(currentPageBody) == 0 && pageIndex > 0 {
			logging.Logf(logging.Info, "Pagination (Link Header): Received empty body on page %d (index %d). Stopping.", pageIndex+1, pageIndex)
			break
		}

		// Parse current page and extract results
		pageParsed := gjson.ParseBytes(currentPageBody)
		resultsData := pageParsed.Get(pagCfg.ResultsField)
		currentPageItemCount := 0 // Count items on this page
		if resultsData.Exists() && resultsData.IsArray() {
			items := resultsData.Array()
			currentPageItemCount = len(items)
			for _, item := range items {
				mergedResults = append(mergedResults, json.RawMessage(item.Raw))
			}
			logging.Logf(logging.Debug, "Pagination (Link Header): Extracted %d items on page %d (index %d). Total so far: %d", currentPageItemCount, pageIndex+1, pageIndex, len(mergedResults))
		} else {
			if pageIndex == 0 {
				logging.Logf(logging.Warning, "Pagination (Link Header): Results field '%s' not found or not an array in initial response.", pagCfg.ResultsField)
			} else {
				// Don't necessarily stop if results field missing on subsequent pages,
				// the Link header is the primary stop condition. But do log it.
				logging.Logf(logging.Warning, "Pagination (Link Header): Results field '%s' not found or not an array on page %d (index %d).", pagCfg.ResultsField, pageIndex+1, pageIndex)
			}
		}

		// --- Stop Condition: Find 'next' link header ---
		nextLinkURL, found := parseLinkHeader(currentPageResp.Header)
		if !found {
			logging.Logf(logging.Info, "Pagination (Link Header): No 'next' link found in headers. Stopping.")
			break
		}
		logging.Logf(logging.Debug, "Pagination (Link Header): Found next link URL: %s", nextLinkURL)

		// --- Check MaxPages BEFORE preparing the next request ---
		nextPageIndex := pageIndex + 1
		if pagCfg.MaxPages > 0 && nextPageIndex >= pagCfg.MaxPages {
			logging.Logf(logging.Info, "Pagination (Link Header): Reached configured max_pages (%d). Stopping.", pagCfg.MaxPages)
			break
		}

		// --- Prepare for Next Page ---
		nextReq, err := copyRequest(currentReq)
		if err != nil {
			return marshalResults(mergedResults), fmt.Errorf("failed copy request for next link header page: %w", err)
		}

		// Modify the request based on the link header
		err = modifyRequestForLinkHeader(nextReq, currentReq.URL, nextLinkURL)
		if err != nil {
			return marshalResults(mergedResults), err // Error resolving/parsing URL
		}

		// Execute the next request
		resp, bodyBytes, execErr := ExecuteRequest(client, nextReq, effectiveAuthType, authCreds, retryCfg, logLevel)
		if execErr != nil {
			logging.Logf(logging.Error, "Pagination (Link Header): Failed to fetch next page using link '%s': %v. Stopping.", nextLinkURL, execErr)
			return marshalResults(mergedResults), execErr // Return partial results and the error
		}
		if resp != nil {
			resp.Body.Close()
		}
		currentPageBody = bodyBytes
		currentPageResp = resp
		currentReq = nextReq // Update currentReq for the *next* iteration's copyRequest
	}
	return marshalResults(mergedResults), nil
}

// ========================= Helpers =========================

// getTotalRecords extracts the total record count from body or headers based on config.
func getTotalRecords(pageParsed gjson.Result, resp *http.Response, pagCfg *config.PaginationConfig) int {
	totalRecords := -1
	if pagCfg.TotalField != "" {
		totalVal := pageParsed.Get(pagCfg.TotalField)
		if totalVal.Exists() && totalVal.Type == gjson.Number {
			totalRecords = int(totalVal.Int())
			logging.Logf(logging.Debug, "Pagination: Found total records %d from body field '%s'", totalRecords, pagCfg.TotalField)
		} else if totalVal.Exists() {
			logging.Logf(logging.Warning, "Pagination: Total field '%s' exists but is not a number (type: %s). Ignoring.", pagCfg.TotalField, totalVal.Type)
		}
	}
	// Only check header if body didn't provide a valid total
	if totalRecords == -1 && pagCfg.TotalHeader != "" {
		totalStr := resp.Header.Get(pagCfg.TotalHeader)
		if totalStr != "" {
			if totalInt, err := strconv.Atoi(totalStr); err == nil {
				totalRecords = totalInt
				logging.Logf(logging.Debug, "Pagination: Found total records %d from header '%s'", totalRecords, pagCfg.TotalHeader)
			} else {
				logging.Logf(logging.Warning, "Pagination: Total header '%s' value '%s' is not a valid integer. Ignoring. Error: %v", pagCfg.TotalHeader, totalStr, err)
			}
		}
	}
	return totalRecords
}

// getNextCursor extracts the next cursor value from body or headers based on config.
func getNextCursor(pageParsed gjson.Result, resp *http.Response, pagCfg *config.PaginationConfig) string {
	if pagCfg.NextField != "" {
		cursorResult := pageParsed.Get(pagCfg.NextField)
		// Check if exists, is not null, and is not an empty string
		if cursorResult.Exists() && cursorResult.Type != gjson.Null && cursorResult.String() != "" {
			return cursorResult.String()
		}
	} else if pagCfg.NextHeader != "" {
		// Return header value directly, empty string if not found
		return resp.Header.Get(pagCfg.NextHeader)
	}
	// No cursor found
	return ""
}

// modifyRequestQueryForOffsetPage updates the URL query parameters for the next request in offset/page modes.
func modifyRequestQueryForOffsetPage(nextReq *http.Request, pagCfg *config.PaginationConfig, offsetStr, limitStr, pageStr string) error { // Accept config by pointer
	currentURL := nextReq.URL
	// Start with a clean copy of the URL structure but keep existing query params
	newURL := url.URL{
		Scheme:     currentURL.Scheme,
		Opaque:     currentURL.Opaque,
		User:       currentURL.User,
		Host:       currentURL.Host,
		Path:       currentURL.Path,
		ForceQuery: currentURL.ForceQuery, // Preserve if ForceQuery was true
		Fragment:   currentURL.Fragment,   // Preserve fragment
	}
	// Get existing query parameters
	newQuery := currentURL.Query() // Use Query() to handle parsing

	// Set the required pagination parameters, overwriting if they already exist
	if pagCfg.Strategy == "offset" {
		newQuery.Set(pagCfg.OffsetParam, offsetStr)
		newQuery.Set(pagCfg.LimitParam, limitStr)
		// Remove potentially conflicting page/size params if strategy is strictly offset
		if pagCfg.PageParam != "" {
			newQuery.Del(pagCfg.PageParam)
		}
		if pagCfg.SizeParam != "" {
			newQuery.Del(pagCfg.SizeParam)
		}
	} else { // page strategy
		newQuery.Set(pagCfg.PageParam, pageStr)
		newQuery.Set(pagCfg.LimitParam, limitStr) // Use LimitParam (might be same as SizeParam)
		// SizeParam might be different from LimitParam, ensure it's also set or removed correctly
		if pagCfg.SizeParam != "" && pagCfg.SizeParam != pagCfg.LimitParam {
			newQuery.Set(pagCfg.SizeParam, limitStr) // Assume size is same as limit if not explicitly different
		}
		// Remove potentially conflicting offset param if strategy is strictly page
		if pagCfg.OffsetParam != "" {
			newQuery.Del(pagCfg.OffsetParam)
		}
	}

	// Encode the modified query parameters back into the URL
	newURL.RawQuery = newQuery.Encode()
	nextReq.URL = &newURL // Update the request's URL
	logging.Logf(logging.Debug, "Pagination (Query): Constructed next URL: %s", nextReq.URL.String())
	return nil
}

// modifyRequestBodyForOffsetPage updates the JSON body for the next request in offset/page modes.
func modifyRequestBodyForOffsetPage(nextReq *http.Request, pagCfg *config.PaginationConfig, offsetStr, limitStr, pageStr string) error { // Accept config by pointer
	originalBodyBytes, err := readRequestBody(nextReq)
	if err != nil {
		return fmt.Errorf("failed read request body for modification: %w", err)
	}

	var reqJSON map[string]interface{}
	if len(originalBodyBytes) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(originalBodyBytes))
		decoder.UseNumber() // Important for preserving number types if needed later
		if err := decoder.Decode(&reqJSON); err != nil {
			// Provide more context on JSON parsing error
			snippet := string(originalBodyBytes)
			if len(snippet) > 200 {
				snippet = snippet[:200] + "..."
			}
			return fmt.Errorf("failed parse request body JSON: %w. Body snippet: %s", err, snippet)
		}
	} else {
		// Start with an empty map if there was no body
		reqJSON = make(map[string]interface{})
	}

	// Find or create the target map *at the specified path*
	targetMap, findErr := findOrCreateTargetPath(reqJSON, pagCfg.BodyPath)
	if findErr != nil {
		return fmt.Errorf("failed find/create body path '%s': %w", pagCfg.BodyPath, findErr)
	}

	// Set the pagination parameters directly into the targetMap
	if pagCfg.Strategy == "offset" {
		// Convert offset/limit to numbers if possible for JSON consistency, else keep as string
		if offsetNum, err := strconv.Atoi(offsetStr); err == nil {
			targetMap[pagCfg.OffsetParam] = json.Number(strconv.Itoa(offsetNum))
		} else {
			targetMap[pagCfg.OffsetParam] = offsetStr
		}
		if limitNum, err := strconv.Atoi(limitStr); err == nil {
			targetMap[pagCfg.LimitParam] = json.Number(strconv.Itoa(limitNum))
		} else {
			targetMap[pagCfg.LimitParam] = limitStr
		}
		// Remove potentially conflicting page/size params from the target map
		if pagCfg.PageParam != "" {
			delete(targetMap, pagCfg.PageParam)
		}
		if pagCfg.SizeParam != "" {
			delete(targetMap, pagCfg.SizeParam)
		}
	} else { // page strategy
		if pageNum, err := strconv.Atoi(pageStr); err == nil {
			targetMap[pagCfg.PageParam] = json.Number(strconv.Itoa(pageNum))
		} else {
			targetMap[pagCfg.PageParam] = pageStr
		}
		if limitNum, err := strconv.Atoi(limitStr); err == nil {
			targetMap[pagCfg.LimitParam] = json.Number(strconv.Itoa(limitNum))
			// Ensure SizeParam reflects Limit if they are supposed to be the same
			if pagCfg.SizeParam != "" && pagCfg.SizeParam == pagCfg.LimitParam {
				targetMap[pagCfg.SizeParam] = json.Number(strconv.Itoa(limitNum))
			}
		} else {
			targetMap[pagCfg.LimitParam] = limitStr
			if pagCfg.SizeParam != "" && pagCfg.SizeParam == pagCfg.LimitParam {
				targetMap[pagCfg.SizeParam] = limitStr
			}
		}
		// Handle SizeParam if different from LimitParam
		if pagCfg.SizeParam != "" && pagCfg.SizeParam != pagCfg.LimitParam {
			if sizeNum, err := strconv.Atoi(limitStr); err == nil { // Use limitStr for size value too
				targetMap[pagCfg.SizeParam] = json.Number(strconv.Itoa(sizeNum))
			} else {
				targetMap[pagCfg.SizeParam] = limitStr
			}
		}
		// Remove potentially conflicting offset param from the target map
		if pagCfg.OffsetParam != "" {
			delete(targetMap, pagCfg.OffsetParam)
		}
	}

	// Marshal the *original top-level* JSON structure back to bytes
	updatedBodyBytes, err := json.Marshal(reqJSON)
	if err != nil {
		return fmt.Errorf("failed marshal updated request body: %w", err)
	}

	// Update the request body and related fields
	nextReq.Body = io.NopCloser(bytes.NewReader(updatedBodyBytes))
	nextReq.ContentLength = int64(len(updatedBodyBytes))
	// Ensure GetBody is set so the new body can be re-read on retries
	nextReq.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(updatedBodyBytes)), nil
	}
	// Ensure Content-Type is set if we're sending JSON
	if nextReq.Header.Get("Content-Type") == "" {
		nextReq.Header.Set("Content-Type", "application/json")
	}
	logging.Logf(logging.Debug, "Pagination (Body): Updated body for path '%s': %s", pagCfg.BodyPath, string(updatedBodyBytes))
	return nil
}

// modifyRequestForCursor modifies the nextReq (URL or body) based on the cursor usage mode.
func modifyRequestForCursor(nextReq *http.Request, currentURL *url.URL, pagCfg *config.PaginationConfig, nextCursor string) error { // Accept config by pointer
	switch pagCfg.CursorUsageMode { // Use the pointer's field
	case "url":
		// The cursor itself is a full URL (potentially relative)
		absoluteNextURL, err := makeAbsoluteURL(currentURL, nextCursor)
		if err != nil {
			return fmt.Errorf("failed resolve cursor URL '%s' relative to '%s': %w", nextCursor, currentURL.String(), err)
		}
		newURL, err := url.Parse(absoluteNextURL)
		if err != nil {
			return fmt.Errorf("failed parse absolute cursor URL '%s': %w", absoluteNextURL, err)
		}
		// Replace the request's URL entirely
		nextReq.URL = newURL
		// Typically, if the cursor is a URL, it implies a GET request with no body
		nextReq.Method = "GET"
		nextReq.Body = nil
		nextReq.GetBody = nil
		nextReq.ContentLength = 0
		nextReq.Header.Del("Content-Type") // Remove potential Content-Type from previous POST/PUT
		logging.Logf(logging.Debug, "Pagination (Cursor URL): Set next request URL to: %s", nextReq.URL.String())
	case "query":
		// Add/update the cursor as a query parameter
		baseURL := nextReq.URL // Use the URL from the (potentially already modified) nextReq
		newQuery := baseURL.Query()
		newQuery.Set(pagCfg.CursorParam, nextCursor)
		// Rebuild the URL with the updated query string
		newURL := *baseURL // Create a copy
		newURL.RawQuery = newQuery.Encode()
		nextReq.URL = &newURL
		logging.Logf(logging.Debug, "Pagination (Cursor Query): Set param '%s=%s'. New URL: %s", pagCfg.CursorParam, nextCursor, nextReq.URL.String())
	case "body":
		// Add/update the cursor within the JSON request body
		originalBodyBytes, err := readRequestBody(nextReq)
		if err != nil {
			return fmt.Errorf("failed read request body for cursor modification: %w", err)
		}
		var reqJSON map[string]interface{}
		if len(originalBodyBytes) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(originalBodyBytes))
			decoder.UseNumber()
			if err := decoder.Decode(&reqJSON); err != nil {
				// Provide more context on JSON parsing error
				snippet := string(originalBodyBytes)
				if len(snippet) > 200 {
					snippet = snippet[:200] + "..."
				}
				return fmt.Errorf("failed parse request body JSON for cursor: %w. Body snippet: %s", err, snippet)
			}
		} else {
			reqJSON = make(map[string]interface{})
		}
		// Find/create the target map *at the specified path*
		targetMap, findErr := findOrCreateTargetPath(reqJSON, pagCfg.BodyPath)
		if findErr != nil {
			return fmt.Errorf("failed find/create body path '%s' for cursor: %w", pagCfg.BodyPath, findErr)
		}
		// Set the cursor parameter directly into the targetMap
		targetMap[pagCfg.CursorParam] = nextCursor

		// Marshal the *original top-level* JSON structure back
		updatedBodyBytes, err := json.Marshal(reqJSON)
		if err != nil {
			return fmt.Errorf("failed marshal updated request body for cursor: %w", err)
		}
		// Update the request body
		nextReq.Body = io.NopCloser(bytes.NewReader(updatedBodyBytes))
		nextReq.ContentLength = int64(len(updatedBodyBytes))
		nextReq.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(updatedBodyBytes)), nil
		}
		if nextReq.Header.Get("Content-Type") == "" {
			nextReq.Header.Set("Content-Type", "application/json")
		}
		logging.Logf(logging.Debug, "Pagination (Cursor Body): Updated body path '%s' with param '%s': %s", pagCfg.BodyPath, pagCfg.CursorParam, string(updatedBodyBytes))
	default:
		// Validation should prevent this, but return error if reached.
		return fmt.Errorf("internal error: unhandled cursor_usage_mode: '%s'", pagCfg.CursorUsageMode)
	}
	return nil
}

// modifyRequestForLinkHeader modifies the nextReq URL based on the Link header.
func modifyRequestForLinkHeader(nextReq *http.Request, currentURL *url.URL, nextLinkURL string) error {
	absoluteNextURL, err := makeAbsoluteURL(currentURL, nextLinkURL)
	if err != nil {
		return fmt.Errorf("failed resolve link header URL '%s' relative to '%s': %w", nextLinkURL, currentURL.String(), err)
	}
	newURL, err := url.Parse(absoluteNextURL)
	if err != nil {
		return fmt.Errorf("failed parse absolute link header URL '%s': %w", absoluteNextURL, err)
	}
	// Replace URL, assume GET, remove body
	nextReq.URL = newURL
	nextReq.Method = "GET"
	nextReq.Body = nil
	nextReq.GetBody = nil
	nextReq.ContentLength = 0
	nextReq.Header.Del("Content-Type") // Remove potential Content-Type from previous POST/PUT
	logging.Logf(logging.Debug, "Pagination (Link Header): Set next request URL to: %s", nextReq.URL.String())
	return nil
}

// marshalResults converts raw JSON messages to a final JSON array string.
func marshalResults(results []json.RawMessage) string {
	if len(results) == 0 {
		return "[]"
	}
	// Efficiently join the raw messages with commas
	var buf bytes.Buffer
	buf.WriteString("[")
	for i, r := range results {
		buf.Write(r)
		if i < len(results)-1 {
			buf.WriteString(",")
		}
	}
	buf.WriteString("]")
	return buf.String()
}

// makeAbsoluteURL resolves a relative URL against a base URL.
func makeAbsoluteURL(originalURL *url.URL, nextURL string) (string, error) {
	parsedNext, err := url.Parse(nextURL)
	if err != nil {
		return "", err // Invalid nextURL syntax
	}
	// If original URL is nil or next URL is already absolute, return next URL as is
	if originalURL == nil || parsedNext.IsAbs() {
		return parsedNext.String(), nil
	}
	// Resolve nextURL relative to originalURL
	return originalURL.ResolveReference(parsedNext).String(), nil
}

// findOrCreateTargetPath finds or creates the map *at the end* of the specified path.
// Example: path "a.b.c" returns the map associated with key "c".
// If the path is empty, it returns the original root map.
func findOrCreateTargetPath(data map[string]interface{}, path string) (map[string]interface{}, error) {
	if path == "" {
		return data, nil // Return root if path is empty
	}
	// *** Add specific check for "." ***
	if path == "." {
		return nil, fmt.Errorf("invalid body_path: path cannot be just '.'")
	}

	parts := strings.Split(path, ".")
	current := data // Start at the root map

	for i, part := range parts {
		// Check for empty segment *first*
		if part == "" {
			// Determine context of the empty segment
			// The explicit "." check above handles the main case for i==0
			if i == 0 { // Leading dot ".a.b"
				return nil, fmt.Errorf("invalid body_path: path cannot start with '.' (%s)", path)
			} else if i == len(parts)-1 { // Trailing dot "a.b."
				return nil, fmt.Errorf("invalid body_path: path cannot end with '.' (%s)", path)
			} else { // Multiple dots "a..b"
				return nil, fmt.Errorf("invalid body_path: path cannot contain empty segments ('..') (%s)", path)
			}
		}

		// Check if we are at the last part of the path
		isLastPart := (i == len(parts)-1)

		nextVal, exists := current[part]

		if !exists {
			// Segment doesn't exist, create a new map for it
			newMap := make(map[string]interface{})
			current[part] = newMap // Add the new map to the *current* map
			if isLastPart {
				// If this is the last part, we've created the target map, return it
				return newMap, nil
			}
			// Otherwise, move into the newly created map for the next iteration
			current = newMap
		} else {
			// Segment exists, check if it's a map
			if nextMap, ok := nextVal.(map[string]interface{}); ok {
				if isLastPart {
					// If this is the last part and it's an existing map, return it
					return nextMap, nil
				}
				// Otherwise, move into the existing map
				current = nextMap
			} else {
				// Segment exists but is not a map, this is an error
				if isLastPart {
					// If it's the last part, the target location exists but is not a suitable map
					return nil, fmt.Errorf("field '%s' at end of path '%s' exists but is not a map (type: %T)", part, path, nextVal)
				} else {
					// If it's an intermediate part, we cannot traverse further
					return nil, fmt.Errorf("intermediate field '%s' in path '%s' is not a map (type: %T)", part, path, nextVal)
				}
			}
		}
	}

	// This state should not be reached for non-empty paths due to the logic above.
	return nil, fmt.Errorf("internal error: findOrCreateTargetPath reached unexpected state for path '%s'", path)
}

// copyRequest creates a usable copy of an http.Request. Crucially handles GetBody.
func copyRequest(req *http.Request) (*http.Request, error) {
	// Use Clone to copy most fields including headers, method, context, etc.
	newReq := req.Clone(req.Context())

	// Deep copy URL and UserInfo if they exist
	if req.URL != nil {
		newURLVal := *req.URL
		if req.URL.User != nil {
			newUserVal := *req.URL.User
			newURLVal.User = &newUserVal
		}
		newReq.URL = &newURLVal
	}

	// Handle body copying and GetBody setup
	if req.Body != nil {
		// If GetBody exists, use it for the new request as well.
		if req.GetBody != nil {
			bodyReadCloser, err := req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("copyRequest: failed GetBody from original request: %w", err)
			}
			newReq.Body = bodyReadCloser
			newReq.GetBody = req.GetBody // Reuse the original GetBody func
			newReq.ContentLength = req.ContentLength
		} else {
			// If no GetBody, read the original body, store it, and set GetBody on *both* requests.
			// This consumes the original req.Body but makes both requests retryable.
			logging.Logf(logging.Warning, "copyRequest: Original request has body but no GetBody. Reading body now; original req.Body will be consumed.")
			bodyBytes, err := io.ReadAll(req.Body)
			req.Body.Close() // Close original after reading
			if err != nil {
				return nil, fmt.Errorf("copyRequest: failed read original body: %w", err)
			}

			// Set body and GetBody for the new request
			newReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			newReq.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(bodyBytes)), nil
			}
			newReq.ContentLength = int64(len(bodyBytes))

			// Also reset the original request's body and set GetBody for it
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			req.GetBody = newReq.GetBody // Share the same GetBody func
			req.ContentLength = newReq.ContentLength
		}
	} // else: req.Body was nil, so newReq.Body is also nil (correct)

	return newReq, nil
}

// readRequestBody safely reads request body bytes, ensuring GetBody is set for future reads if possible.
func readRequestBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil // No body to read
	}

	if req.GetBody != nil {
		// Preferred way: use GetBody to get a fresh reader
		bodyReadCloser, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("readRequestBody: failed GetBody: %w", err)
		}
		defer bodyReadCloser.Close() // Ensure the reader from GetBody is closed
		bodyBytes, err := io.ReadAll(bodyReadCloser)
		if err != nil {
			return nil, fmt.Errorf("readRequestBody: failed read from GetBody stream: %w", err)
		}
		return bodyBytes, nil
	}

	// Fallback: No GetBody available. Read directly, consuming the body.
	// Set GetBody afterwards if possible.
	logging.Logf(logging.Warning, "readRequestBody: Request has body but no GetBody. Reading body directly; req.Body will be consumed.")
	bodyBytes, err := io.ReadAll(req.Body)
	req.Body.Close() // Close original after reading
	if err != nil {
		return nil, fmt.Errorf("readRequestBody: failed read directly: %w", err)
	}

	// Attempt to make the body readable again by setting GetBody
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodyBytes)), nil
	}
	req.ContentLength = int64(len(bodyBytes)) // Update ContentLength as well

	return bodyBytes, nil
}

// linkHeaderRegex parses Link header parts - improved version.
// Captures URL in group 1, and rel value (unquoted) in group 2.
// Further improved: Allow spaces around the '=' in rel=
var linkHeaderRegex = regexp.MustCompile(`<([^>]+)>\s*;\s*rel\s*=\s*"?([^"]*)"?`)

// parseLinkHeader finds the URL for rel="next" in Link headers.
func parseLinkHeader(headers http.Header) (string, bool) {
	for _, linkValue := range headers.Values("Link") {
		// Split header potentially containing multiple links separated by comma
		parts := strings.Split(linkValue, ",")
		for _, part := range parts {
			matches := linkHeaderRegex.FindStringSubmatch(strings.TrimSpace(part))
			// Expect 3 parts: full match, URL, rel value
			if len(matches) == 3 {
				urlPart := strings.TrimSpace(matches[1])
				relPart := strings.ToLower(strings.TrimSpace(matches[2]))
				// Check if the relation is exactly "next"
				if relPart == "next" {
					return urlPart, true
				}
			}
		}
	}
	return "", false
}

