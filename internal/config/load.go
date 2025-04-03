package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadConfig reads, parses, and validates the YAML configuration file.
func LoadConfig(filename string) (*Config, error) {
	fileBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file '%s': %w", filename, err)
	}

	var config Config
	err = yaml.Unmarshal(fileBytes, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML in '%s': %w", filename, err)
	}

	// --- Apply Minimal Defaults Before Validation ---
	if config.Retry.MaxAttempts <= 0 { config.Retry.MaxAttempts = 1 }
	if config.Retry.Backoff <= 0 { config.Retry.Backoff = 1 }
	if config.Logging.Level == "" { config.Logging.Level = "info" }

	// --- Perform Manual Validation ---
	if err := ValidateConfigManually(&config); err != nil { // Call the new top-level manual func
		return nil, err // Error is already formatted
	}

	// --- Validation Passed ---
	return &config, nil
}