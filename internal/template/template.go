package template

import (
	"bytes"
	"fmt"
	"text/template" // Use text/template for general purpose templating

	"api-tool/internal/logging"
)

// Render evaluates a Go template string with the provided data map.
// It returns an error if template parsing fails or if a referenced key
// is missing in the data map (due to Option("missingkey=error")).
func Render(templateName, tmplStr string, data map[string]string) (string, error) {
	if tmplStr == "" {
		return "", nil // Nothing to render
	}

	// Add Option("missingkey=error") to cause errors on missing keys
	tmpl, err := template.New(templateName).Option("missingkey=error").Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse template '%s': %w", templateName, err)
	}

	var buf bytes.Buffer
	// Execute: Passing nil data map or referencing a missing key will now cause an error.
	err = tmpl.Execute(&buf, data)
	if err != nil {
		// Log truncated data for debugging, handle nil case.
		debugData := make(map[string]string)
		if data != nil {
			for k, v := range data {
				if len(v) > 100 {
					debugData[k] = v[:100] + "..."
				} else {
					debugData[k] = v
				}
			}
		} else {
			debugData = nil // Indicate data was nil in log
		}
		logging.Logf(logging.Debug, "Template data (truncated): %v", debugData)
		return "", fmt.Errorf("failed to execute template '%s': %w", templateName, err)
	}

	return buf.String(), nil
}
