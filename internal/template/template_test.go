package template

import (
	"bytes"
	"testing"
	"text/template" // Import text/template directly for isolation test

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTextTemplateMissingKeyErrorOption directly tests the behavior of text/template
// with the Option("missingkey=error"). This helps isolate whether the core
// template engine behaves as expected regarding missing keys.
func TestTextTemplateMissingKeyErrorOption(t *testing.T) {
	tmplStr := "Key: {{.MissingKey}}"
	tmpl, err := template.New("directTest").Option("missingkey=error").Parse(tmplStr)
	require.NoError(t, err, "Parsing the test template should succeed")

	var buf bytes.Buffer
	dataWithMissingKey := map[string]string{"PresentKey": "value"} // Data missing 'MissingKey'

	// Execute with map containing some data but missing the required key
	err = tmpl.Execute(&buf, dataWithMissingKey)
	// Reverted Assertion: Expect an error because missingkey=error is set
	assert.Error(t, err, "Expected error for missing key with missingkey=error")

	// Execute with nil data
	var buf2 bytes.Buffer
	err = tmpl.Execute(&buf2, nil) // Pass nil data
	// Reverted Assertion: Expect an error because missingkey=error is set
	assert.Error(t, err, "Expected error for nil data with missingkey=error")

	// Execute with an empty map
	var buf3 bytes.Buffer
	err = tmpl.Execute(&buf3, map[string]string{}) // Pass empty map
	// Reverted Assertion: Expect an error because missingkey=error is set
	assert.Error(t, err, "Expected error for empty map with missingkey=error")
}

func TestRender(t *testing.T) {
	data := map[string]string{
		"name":    "World",
		"item_id": "12345",
		"api_key": "secret-key",
		"empty":   "",
		"urlPath": "/items/{{.item_id}}", // Example of nested template string
	}

	tests := []struct {
		name         string
		templateName string
		tmplStr      string
		data         map[string]string
		expected     string // Expected output *if successful*
		expectError  bool   // Whether the Render function itself is expected to error
	}{
		{
			name:         "Simple Substitution",
			templateName: "simple",
			tmplStr:      "Hello, {{.name}}!",
			data:         data,
			expected:     "Hello, World!",
			expectError:  false,
		},
		{
			name:         "Multiple Substitutions",
			templateName: "multi",
			tmplStr:      "ID: {{.item_id}}, Key: {{.api_key}}",
			data:         data,
			expected:     "ID: 12345, Key: secret-key",
			expectError:  false,
		},
		{
			name:         "Empty Template String",
			templateName: "emptyTmpl",
			tmplStr:      "",
			data:         data,
			expected:     "",
			expectError:  false,
		},
		{
			name:         "Nil Data",
			templateName: "nilData",
			tmplStr:      "Value: {{.some_key}}",
			data:         nil,
			expected:     "",   // Expect empty string because execution fails
			expectError:  true, // Reverted: Expect error due to missingkey=error
		},
		{
			name:         "Empty Data Map",
			templateName: "emptyDataMap",
			tmplStr:      "Value: {{.some_key}}",
			data:         map[string]string{},
			expected:     "",   // Expect empty string because execution fails
			expectError:  true, // Reverted: Expect error due to missingkey=error
		},
		{
			name:         "Missing Key in Data",
			templateName: "missingKey",
			tmplStr:      "Hello, {{.missing_name}}!",
			data:         data,
			expected:     "",   // Expect empty string because execution fails
			expectError:  true, // Reverted: Expect error due to missingkey=error
		},
		{
			name:         "Invalid Template Syntax",
			templateName: "invalidSyntax",
			tmplStr:      "Hello, {{ .name }!", // Missing closing braces
			data:         data,
			expected:     "",
			expectError:  true, // Parsing error is expected
		},
		{
			name:         "Substitute Empty Value",
			templateName: "subEmpty",
			tmplStr:      "Value is '{{.empty}}'",
			data:         data,
			expected:     "Value is ''",
			expectError:  false,
		},
		{
			name:         "Template with No Substitutions",
			templateName: "noSubs",
			tmplStr:      "Just plain text.",
			data:         data,
			expected:     "Just plain text.",
			expectError:  false,
		},
		{
			name:         "Substitute String Containing Template Syntax",
			templateName: "nestedSyntax",
			tmplStr:      "Path: {{.urlPath}}",
			data:         data,
			expected:     "Path: /items/{{.item_id}}", // Literal substitution
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := Render(tt.templateName, tt.tmplStr, tt.data)

			if tt.expectError {
				assert.Error(t, err, "Expected an error for test case: %s", tt.name)
			} else {
				assert.NoError(t, err, "Expected no error for test case: %s. Error: %v", tt.name, err)
			}
			// Assert expected output only if no error was expected *or* if it was just a parse error
			// (execution errors mean output shouldn't be checked)
			if !tt.expectError || tt.name == "Invalid Template Syntax" {
				assert.Equal(t, tt.expected, actual, "Output mismatch for test case: %s", tt.name)
			} else {
				// For execution errors (missing key, nil data), the output should be empty
				assert.Empty(t, actual, "Output should be empty when template execution fails for test case: %s", tt.name)
			}
		})
	}
}
