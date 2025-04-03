package executor

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"api-tool/internal/config"
	"api-tool/internal/logging"
	// REMOVED: "github.com/xinsnake/go-http-digest-auth-client"
)

// sleepFunc defines the signature for a function that pauses execution.
// Used to allow mocking time.Sleep during tests.
type sleepFunc func(time.Duration)

// DefaultSleep is the default sleep function (time.Sleep).
// It's exported to be potentially modified by tests.
var DefaultSleep sleepFunc = time.Sleep

// ExecuteRequest sends an HTTP request, handling retries.
// Digest authentication is now handled by the client's Transport.
// It uses an injectable sleep function (DefaultSleep) for testing.
func ExecuteRequest(
	client *http.Client,
	req *http.Request,
	effectiveAuthType string, // Still needed for logging/context potentially, but not for execution logic here
	authCreds map[string]string, // Potentially needed if retry logic needs to re-auth (unlikely with RoundTripper)
	retryCfg config.RetryConfig,
	logLevel int,
) (*http.Response, []byte, error) {

	attempts := 0
	maxAttempts := retryCfg.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 1 // Ensure at least one attempt
	}
	backoffDuration := time.Duration(retryCfg.Backoff) * time.Second

	var lastErr error // Stores the last error encountered, potentially across retries

	// --- Retry Loop ---
	for attempts < maxAttempts {
		attempts++
		if maxAttempts > 1 {
			logging.Logf(logging.Debug, "Request attempt %d/%d for %s %s", attempts, maxAttempts, req.Method, req.URL.String())
		}

		// --- Ensure Request Body Can Be Re-read ---
		// Store body bytes ONLY if we might need to retry and GetBody isn't set.
		// If GetBody is set, we trust it to provide fresh readers.
		var originalBodyBytes []byte // To restore body if read here
		// var bodyReadForRetry bool // No longer needed directly here

		if req.Body != nil && req.GetBody == nil && maxAttempts > 1 {
			// Read the body now if retries are possible and GetBody isn't available
			logging.Logf(logging.Debug, "Reading request body for potential retry as GetBody is not set.")
			var readErr error
			bodyReadCloser := req.Body
			originalBodyBytes, readErr = io.ReadAll(bodyReadCloser)
			bodyReadCloser.Close() // Close original body after reading
			if readErr != nil {
				// If we can't even read the body once, it's a fatal error for this request.
				return nil, nil, fmt.Errorf("failed to read request body for potential retry: %w", readErr)
			}
			req.Body = io.NopCloser(bytes.NewReader(originalBodyBytes)) // Replace body for this attempt
			// ALSO set GetBody so it *can* be retried by http.Client internals if needed
			req.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(originalBodyBytes)), nil
			}
			req.ContentLength = int64(len(originalBodyBytes))
			// bodyReadForRetry = true // No longer needed directly here
		} else if req.GetBody != nil {
			// If GetBody is available, use it to get a fresh body reader for this attempt
			// The http.Client will handle this internally if needed for retries or redirects.
			// We might still need to reset it here if our *own* retry logic runs.
			newBody, err := req.GetBody()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to reset request body using GetBody for retry attempt: %w", err)
			}
			// Ensure the previous body reader is closed if it exists (might be from previous attempt)
			if req.Body != nil {
				req.Body.Close()
			}
			req.Body = newBody
		}
		// If req.Body was nil initially, nothing needed.

		// --- Perform the HTTP Request using the configured client ---
		// The client's Transport will now handle Digest, NTLM, etc. automatically.
		resp, err := client.Do(req)

		// --- Handle Request Execution Error (Network Error, etc.) ---
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err) // Store as the last known error
			logging.Logf(logging.Info, "Attempt %d failed: %v", attempts, err)
			// Check if we should retry this error
			if attempts < maxAttempts {
				logging.Logf(logging.Info, "Retrying in %v...", backoffDuration)
				DefaultSleep(backoffDuration) // Use the injectable sleep function
				continue                      // Go to next iteration of the retry loop
			}
			// Max attempts reached for this error
			break // Exit retry loop
		}

		// --- Process Successful Response ---
		// Read response body immediately
		bodyBytes, readErr := io.ReadAll(resp.Body)
		resp.Body.Close() // Close the original body reader
		if readErr != nil {
			// Treat body read error as fatal for this attempt, store error
			lastErr = fmt.Errorf("failed to read response body (status %d): %w", resp.StatusCode, readErr)
			// Return the response headers wrapper but nil body bytes
			// Do not retry body read errors.
			return resp, nil, lastErr
		}
		// Replace response body with a reusable reader for potential downstream use
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// --- Check Status Code for Retry ---
		statusCode := resp.StatusCode
		isRetryable := false
		if statusCode >= 500 && statusCode < 600 { // Basic check for server errors
			isRetryable = true
			// Check exclude list
			for _, excludeCode := range retryCfg.ExcludeErrors {
				if statusCode == excludeCode {
					isRetryable = false
					break
				}
			}
		}
		// TODO: Allow configuring 4xx codes as retryable? (e.g., 429 Too Many Requests)

		if !isRetryable {
			// Successful response or non-retryable error code
			logging.Logf(logging.Debug, "Attempt %d successful with status %d or non-retryable error.", attempts, statusCode)
			return resp, bodyBytes, nil // Return successful result
		}

		// --- Handle Retryable Status Code ---
		lastErr = fmt.Errorf("received retryable status code %d", statusCode) // Store error
		logging.Logf(logging.Info, "Attempt %d failed: %v", attempts, lastErr)

		if attempts < maxAttempts {
			logging.Logf(logging.Info, "Retrying in %v...", backoffDuration)
			DefaultSleep(backoffDuration) // Use the injectable sleep function
			// Continue to the next iteration of the loop
		}
		// If max attempts reached, the loop will terminate naturally
	} // --- End of Retry Loop ---

	// If the loop finished, it means all attempts failed. Return the last recorded error.
	// Response and bodyBytes should be nil in this failure case.
	return nil, nil, fmt.Errorf("request failed after %d attempts: %w", maxAttempts, lastErr)
}

// ExtractHeaderValue extracts a value from a response header using a regex.
func ExtractHeaderValue(resp *http.Response, extractionExpr string) (string, error) {
	if !strings.HasPrefix(extractionExpr, "header:") {
		return "", fmt.Errorf("invalid header extraction expression format: %s", extractionExpr)
	}

	parts := strings.SplitN(strings.TrimPrefix(extractionExpr, "header:"), ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid header extraction expression format (missing regex): %s", extractionExpr)
	}

	headerName := strings.TrimSpace(parts[0])
	regexPattern := parts[1]

	if headerName == "" || regexPattern == "" {
		return "", fmt.Errorf("invalid header extraction expression format (empty header name or regex): %s", extractionExpr)
	}

	headerValue := resp.Header.Get(headerName)
	// Header not found is now treated as an error condition for extraction.
	// If optional extraction is needed, the caller (chain runner) should handle the error.
	if headerValue == "" && resp.Header.Get(headerName) == "" { // Check again in case header name case was wrong (Header.Get handles canonicalization)
		// Re-check ensures we didn't miss it due to case mismatch only
		if _, headerPresent := resp.Header[http.CanonicalHeaderKey(headerName)]; !headerPresent {
			return "", fmt.Errorf("header '%s' not found in response", headerName)
		}
		// If header is present but empty, let regex decide
	}

	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return "", fmt.Errorf("invalid regex pattern '%s': %w", regexPattern, err)
	}

	matches := re.FindStringSubmatch(headerValue)
	if len(matches) < 2 { // Need at least full match + 1 capture group
		return "", fmt.Errorf("regex '%s' did not match or capture a group in header '%s' value '%s'", regexPattern, headerName, headerValue)
	}

	// Return the first captured group
	return matches[1], nil
}