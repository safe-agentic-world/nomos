package audit

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/ai-developer-project/janus/internal/redact"
)

type Event struct {
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"`
	TraceID     string    `json:"trace_id"`
	ActionID    string    `json:"action_id,omitempty"`
	ActionType  string    `json:"action_type,omitempty"`
	Resource    string    `json:"resource,omitempty"`
	Principal   string    `json:"principal,omitempty"`
	Agent       string    `json:"agent,omitempty"`
	Environment string    `json:"environment,omitempty"`
	Decision    string    `json:"decision,omitempty"`
	Reason      string    `json:"reason,omitempty"`
}

type Recorder interface {
	WriteEvent(event Event) error
}

type Writer struct {
	out      io.Writer
	redactor *redact.Redactor
}

func NewWriter(sink string, redactor *redact.Redactor) (*Writer, error) {
	if redactor == nil {
		return nil, errors.New("redactor is required")
	}
	switch sink {
	case "stdout":
		return &Writer{out: os.Stdout, redactor: redactor}, nil
	default:
		return nil, errors.New("unsupported audit sink")
	}
}

func (w *Writer) WriteEvent(event Event) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	redacted := w.redactor.RedactBytes(payload)
	_, err = w.out.Write(append(redacted, '\n'))
	return err
}
