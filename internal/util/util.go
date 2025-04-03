package util

import (
	"os"
	"regexp"
	"strings"
)

// ExpandEnvUniversal expands both Unix-style ($VAR, ${VAR}) and Windows-style (%VAR%) environment variables.
// It first expands Unix-style using os.ExpandEnv, then finds and replaces Windows-style.
func ExpandEnvUniversal(s string) string {
	// Expand Unix-style variables first.
	unixExpanded := os.ExpandEnv(s)

	// Define the regex for Windows-style variables like %VAR%.
	// It looks for alphanumeric characters and underscores between the '%' signs.
	re := regexp.MustCompile(`%([A-Za-z0-9_]+)%`)

	// ReplaceAllStringFunc finds all matches of the regex and calls the provided
	// function for each match. The function's return value replaces the match.
	winExpanded := re.ReplaceAllStringFunc(unixExpanded, func(match string) string {
		// Extract the variable name by removing the surrounding '%' characters.
		varName := match[1 : len(match)-1]

		// Look up the environment variable.
		// os.LookupEnv returns the value and a boolean indicating if it was found.
		if value, ok := os.LookupEnv(varName); ok {
			// If found, return the value.
			return value
		}
		// If not found, return an empty string to effectively remove the placeholder.
		// Alternative: return the original match `match` if you want unmatched vars left as is.
		return ""
	})

	return winExpanded
}


// Snippet returns a short prefix of a byte slice, useful for logging.
func Snippet(b []byte) string {
    const maxLen = 200 // Max length of the snippet
	s := string(b)
	if len(s) > maxLen {
		// Take runes into account to avoid cutting multi-byte characters
        runes := []rune(s)
        if len(runes) > maxLen {
		    return string(runes[:maxLen]) + "..."
        }
        // If rune count is <= maxLen after all, just return the original string
        // (this happens if string has many multi-byte chars but total bytes > maxLen)
	}
	return s
}

// LooksLikeJSON performs a basic check to see if a string starts and ends
// with characters typical of JSON objects or arrays. This is a heuristic
// and does not validate the JSON structure itself.
func LooksLikeJSON(s string) bool {
	trimmed := strings.TrimSpace(s)
	// Check if the trimmed string looks like a JSON object or array.
	return (strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")) ||
		   (strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]"))
}
