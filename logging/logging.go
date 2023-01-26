// Provide application-wide logging with pre-defined log levels.
// It is just concerned with putting strings into the designated
// buffers and thus hides stuff like Panic() or Fatal().
//
// By default logs of level WARNING and ERROR are printed to stderr.
package logging

import (
	"io"
	"log"
	"os"
)

func init() {
	Initialize(LevelWarning, nil, nil)
}

type LogLevel int

const (
	LevelNone LogLevel = iota
	LevelError
	LevelWarning
	LevelInfo
	LevelDebug
)

type logger struct {
	ErrorLogger   *log.Logger
	WarningLogger *log.Logger
	InfoLogger    *log.Logger
	DebugLogger   *log.Logger
}

var currentLogger logger

type nilWriter struct{}

func (ni nilWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

var nilLogger = log.New(nilWriter{}, "", 0)

// Initialize the application wide logger to a specific log level.
// This should ideally be called once at the beginning of the application.
// Custom writers can be specified as well: errWriter will be used for
// log levels ERROR and WARNING, logWriter for everything else.
// These may be set to nil, in which case they default to stdout and stderr.
func Initialize(l LogLevel, logWriter io.Writer, errWriter io.Writer) {
	if logWriter == nil {
		logWriter = os.Stdout
	}

	if errWriter == nil {
		errWriter = os.Stderr
	}

	out := logger{
		ErrorLogger:   nilLogger,
		WarningLogger: nilLogger,
		InfoLogger:    nilLogger,
		DebugLogger:   nilLogger,
	}

	if l >= LevelError {
		out.ErrorLogger = log.New(errWriter, "ERROR: ", log.LstdFlags)
	}

	if l >= LevelWarning {
		out.WarningLogger = log.New(errWriter, "WARNING: ", log.LstdFlags)
	}

	if l >= LevelInfo {
		out.InfoLogger = log.New(logWriter, "INFO: ", log.LstdFlags)
	}

	if l >= LevelDebug {
		out.DebugLogger = log.New(logWriter, "DEBUG: ", log.LstdFlags)
	}

	currentLogger = out
}

func Error(s string) {
	currentLogger.ErrorLogger.Print(s)
}

func Errorf(format string, v ...any) {
	currentLogger.ErrorLogger.Printf(format, v...)
}

func Warning(s string) {
	currentLogger.WarningLogger.Print(s)
}

func Warningf(format string, v ...any) {
	currentLogger.WarningLogger.Printf(format, v...)
}

func Info(s string) {
	currentLogger.InfoLogger.Print(s)
}

func Infof(format string, v ...any) {
	currentLogger.InfoLogger.Printf(format, v...)
}

func Debug(s string) {
	currentLogger.DebugLogger.Print(s)
}

func Debugf(format string, v ...any) {
	currentLogger.DebugLogger.Printf(format, v...)
}
