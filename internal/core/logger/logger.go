// Package logger builds slog handlers: a single default handler (InitLogger - the common case)
// or a logger that fans out across several sinks (New, via slog.NewMultiHandler).
// It also ships ColorHandler, a small colorized text handler.
// InitLogger installs its handler as slog's default, so the rest of the codebase just calls slog.Info / slog.Error / etc.
package logger

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

var (
	colorDebug = "\033[36m"
	colorInfo  = "\033[32m"
	colorWarn  = "\033[33m"
	colorError = "\033[31m"
	colorReset = "\033[0m"
)

// Sink describes one log destination: where to write, in what format, at what
// minimum level. The zero value is INFO text on stdout.
type Sink struct {
	// Level is DEBUG, INFO (default), WARN or ERROR.
	Level string
	// Output is "stdout" (default), "stderr", or a file path.
	Output string
	// Format is "text" (default) or "json".
	Format string
	// Color adds ANSI colors; text format only.
	Color bool
}

// New builds a slog.Logger that fans out to every sink via slog.NewMultiHandler.
// A single sink yields a plain handler (no wrapper). New does NOT install the
// result as the default; call slog.SetDefault yourself, or use InitLogger for
// the single-sink default.
func New(sinks ...Sink) (*slog.Logger, error) {
	if len(sinks) == 0 {
		return nil, fmt.Errorf("logger: at least one sink is required")
	}
	handlers := make([]slog.Handler, 0, len(sinks))
	for _, s := range sinks {
		h, err := buildHandler(s)
		if err != nil {
			return nil, err
		}
		handlers = append(handlers, h)
	}
	if len(handlers) == 1 {
		return slog.New(handlers[0]), nil
	}
	return slog.New(slog.NewMultiHandler(handlers...)), nil
}

// InitLogger builds a single-sink logger and installs it as slog's default.
//
//	levelStr:   DEBUG, INFO (default), WARN, ERROR
//	outputDest: "stdout"/"stderr" or a file path
//	format:     "text" or "json"
//	color:      ANSI color for text format
func InitLogger(levelStr, outputDest, format string, color bool) (*slog.Logger, error) {
	l, err := New(Sink{Level: levelStr, Output: outputDest, Format: format, Color: color})
	if err != nil {
		return nil, err
	}
	slog.SetDefault(l)
	return l, nil
}

// buildHandler turns one Sink into an slog.Handler.
func buildHandler(s Sink) (slog.Handler, error) {
	level := parseLevel(s.Level)
	out, err := openOutput(s.Output)
	if err != nil {
		return nil, err
	}
	format := s.Format
	if format == "" {
		format = "text"
	}
	switch strings.ToLower(format) {
	case "json":
		return slog.NewJSONHandler(out, &slog.HandlerOptions{Level: level}), nil
	case "text":
		if s.Color {
			return NewColorHandler(out, level), nil
		}
		return slog.NewTextHandler(out, &slog.HandlerOptions{Level: level}), nil
	default:
		return nil, fmt.Errorf("invalid log format: %s", format)
	}
}

// parseLevel maps a level name to slog.Level (INFO when empty or unknown).
func parseLevel(s string) slog.Level {
	switch strings.ToUpper(s) {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// openOutput resolves a sink's Output to a writer: stdout (default), stderr, or
// a file opened for append (created if missing).
func openOutput(dest string) (io.Writer, error) {
	switch {
	case dest == "" || strings.EqualFold(dest, "stdout"):
		return os.Stdout, nil
	case strings.EqualFold(dest, "stderr"):
		return os.Stderr, nil
	default:
		return os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	}
}

// ColorHandler is a minimal slog.Handler that writes colorized, single-line
// text records. Construct it with NewColorHandler.
type ColorHandler struct {
	output io.Writer
	level  slog.Level
	attrs  []slog.Attr
	group  string
}

// NewColorHandler returns a ColorHandler writing to w, emitting records at or
// above level.
func NewColorHandler(w io.Writer, level slog.Level) *ColorHandler {
	return &ColorHandler{output: w, level: level}
}

func (c *ColorHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= c.level
}

func (c *ColorHandler) Handle(_ context.Context, r slog.Record) error {
	var buf bytes.Buffer
	var color string
	switch r.Level {
	case slog.LevelDebug:
		color = colorDebug
	case slog.LevelInfo:
		color = colorInfo
	case slog.LevelWarn:
		color = colorWarn
	case slog.LevelError:
		color = colorError
	default:
		color = colorReset
	}
	buf.WriteString(r.Time.Format("2006-01-02T15:04:05.000Z07:00"))
	buf.WriteString(" ")
	buf.WriteString(color)
	buf.WriteString("[")
	buf.WriteString(strings.ToUpper(r.Level.String()))
	buf.WriteString("]")
	buf.WriteString(colorReset)
	buf.WriteString(" ")
	buf.WriteString(r.Message)
	for _, a := range c.attrs {
		a.Value = a.Value.Resolve()
		writeAttr(&buf, c.attrKey(a), a.Value)
	}
	r.Attrs(func(a slog.Attr) bool {
		a.Value = a.Value.Resolve()
		writeAttr(&buf, c.attrKey(a), a.Value)
		return true
	})
	buf.WriteString("\n")
	_, err := c.output.Write(buf.Bytes())
	return err
}

func (c *ColorHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	nh := *c
	nh.attrs = append(append([]slog.Attr{}, c.attrs...), attrs...)
	return &nh
}

func (c *ColorHandler) WithGroup(name string) slog.Handler {
	nh := *c
	if c.group != "" {
		nh.group = c.group + "." + name
	} else {
		nh.group = name
	}
	return &nh
}

func (c *ColorHandler) attrKey(a slog.Attr) string {
	if c.group != "" {
		return c.group + "." + a.Key
	}
	return a.Key
}

func writeAttr(buf *bytes.Buffer, key string, v slog.Value) {
	switch v.Kind() {
	case slog.KindGroup:
		for _, ga := range v.Group() {
			ga.Value = ga.Value.Resolve()
			fmt.Fprintf(buf, " %s.%s=%v", key, ga.Key, ga.Value.Any())
		}
	default:
		fmt.Fprintf(buf, " %s=%v", key, v.Any())
	}
}
