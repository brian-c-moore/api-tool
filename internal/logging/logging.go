package logging

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync/atomic"
)

// Log levels
const (
	None    = 0
	Error   = 1 // Added Error level distinct from Info/Warn
	Warning = 2 // Added Warning level
	Info    = 3
	Debug   = 4
)

var currentLevel atomic.Int32

func init() {
	// Default logger flags
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
    log.SetOutput(os.Stderr) // Log to stderr by default
	// Default level is Info
	currentLevel.Store(Info)
}

// SetLevel sets the global logging level.
func SetLevel(level int) {
	currentLevel.Store(int32(level))
	Logf(Debug, "Log level set to %d", level)
}

// GetLevel returns the current logging level.
func GetLevel() int {
	return int(currentLevel.Load())
}

// ParseLevel converts a string level to an integer level.
func ParseLevel(levelStr string) (int, error) {
	switch strings.ToLower(levelStr) {
	case "none":
		return None, nil
	case "error":
		return Error, nil
	case "warn", "warning":
		return Warning, nil
	case "info":
		return Info, nil
	case "debug":
		return Debug, nil
	default:
		return Info, fmt.Errorf("invalid log level string: '%s'", levelStr)
	}
}

// SetupLogging initializes logging based on a level string.
// Returns the integer log level corresponding to the string.
func SetupLogging(levelStr string) int {
	level, err := ParseLevel(levelStr)
	if err != nil {
		Logf(Warning, "Invalid log level '%s' provided, defaulting to 'info'. %v", levelStr, err)
		level = Info
	}
	SetLevel(level)
    return level
}


// Logf logs a formatted message if the given level is high enough.
func Logf(level int, format string, v ...interface{}) {
	if int32(level) <= currentLevel.Load() {
		prefix := ""
		switch level {
		case Error:
			prefix = "[ERROR] "
		case Warning:
			prefix = "[WARN]  "
		case Info:
			prefix = "[INFO]  "
		case Debug:
			prefix = "[DEBUG] "
        // No prefix for None, but it won't be logged anyway
		}
        // Use log.Printf which adds timestamp/flags automatically
		log.Output(2, fmt.Sprintf(prefix+format, v...)) // log.Output needs call depth 2 to get caller info right
	}
}
