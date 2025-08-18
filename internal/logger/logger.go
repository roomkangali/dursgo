package logger

import (
	"log"
	"os"
	"sync"
)

// LogLevel represents the severity of a log message.
// The order here defines their numerical value (DEBUG=0, INFO=1, etc.)
// A logger set to INFO will show INFO, WARN, ERROR, SUCCESS, but NOT DEBUG.
// A logger set to DEBUG will show ALL levels.
type LogLevel int

const (
	TRACE   LogLevel = iota // 0 - Most verbose, for things like every single request
	DEBUG                   // 1 - Detailed debugging information
	INFO                    // 2 - General information
	WARN                    // 3 - Warnings
	ERROR                   // 4 - Errors
	SUCCESS                 // 5 - Success messages (e.g., vulnerability found)
)

// Logger holds the loggers for different levels and a mutex for concurrent writes.
type Logger struct {
	infoLogger    *log.Logger
	warnLogger    *log.Logger
	errorLogger   *log.Logger
	debugLogger   *log.Logger
	traceLogger   *log.Logger
	successLogger *log.Logger
	mu            sync.Mutex // Mutex to ensure thread-safe writes
	minLevel      LogLevel
}

// NewLogger creates and returns a new Logger instance.
func NewLogger(minLevel LogLevel) *Logger {
	flags := log.Ldate | log.Ltime
	return &Logger{
		infoLogger:    log.New(os.Stdout, "[INFO] ", flags),
		warnLogger:    log.New(os.Stderr, "[WARN] ", flags),
		errorLogger:   log.New(os.Stderr, "[ERROR] ", flags),
		debugLogger:   log.New(os.Stdout, "[DEBUG] ", flags),
		traceLogger:   log.New(os.Stdout, "[TRACE] ", flags),
		successLogger: log.New(os.Stdout, "[SUCCESS] ", flags),
		minLevel:      minLevel,
	}
}

// log prints a message if its level is greater than or equal to the logger's minLevel.
func (l *Logger) log(level LogLevel, logger *log.Logger, format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if level >= l.minLevel {
		logger.Printf(format, v...)
	}
}

// Info logs an informational message.
func (l *Logger) Info(format string, v ...interface{}) {
	l.log(INFO, l.infoLogger, format, v...)
}

// Warn logs a warning message.
func (l *Logger) Warn(format string, v ...interface{}) {
	l.log(WARN, l.warnLogger, format, v...)
}

// Error logs an error message.
func (l *Logger) Error(format string, v ...interface{}) {
	l.log(ERROR, l.errorLogger, format, v...)
}

// Debug logs a debug message. Only active if minLevel is DEBUG.
func (l *Logger) Debug(format string, v ...interface{}) {
	l.log(DEBUG, l.debugLogger, format, v...)
}

// Trace logs a trace message. Only active if minLevel is TRACE.
func (l *Logger) Trace(format string, v ...interface{}) {
	l.log(TRACE, l.traceLogger, format, v...)
}

// Success logs a success message, typically for found vulnerabilities.
func (l *Logger) Success(format string, v ...interface{}) {
	l.log(SUCCESS, l.successLogger, format, v...)
}

// SetMinLevel sets the minimum logging level.
func (l *Logger) SetMinLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.minLevel = level
}
