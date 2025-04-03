package main

import (
	"fmt"
	"log"
	"os"

	"api-tool/internal/app"
	"api-tool/internal/logging"
)

// main is the entry point of the application.
// It initializes the application runner and executes it with command-line arguments.
func main() {
	// Initialize the application runner.
	// Dependencies like config loading, HTTP client creation etc. are handled within the app package.
	runner := app.NewAppRunner()

	// Execute the application logic based on command-line arguments.
	err := runner.Run(os.Args[1:]) // Pass args excluding the program name
	if err != nil {
		// Use standard logger for fatal errors after setup.
		// Logf is used for level-based logging during execution.
		log.Printf("[ERROR] Application execution failed: %v", err)
		// Attempt to provide usage instructions on core errors if appropriate
		if err == app.ErrUsage || err == app.ErrConfigNotFound || err == app.ErrMissingArgs {
			fmt.Fprintln(os.Stderr, "") // Add a newline for separation
			runner.Usage(os.Stderr)
		}
		// Ensure logging level is at least Error before exiting
		if logging.GetLevel() < logging.Error {
			logging.SetLevel(logging.Error)
		}
		os.Exit(1) // Exit with error code
	}

	// Use Logf for final success message if needed, respecting log level
	logging.Logf(logging.Info, "Application completed successfully.")
}
