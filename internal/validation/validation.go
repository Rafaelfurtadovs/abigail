// Package validation describes direct provider availability checks. A provider
// reporting an available name is stronger evidence than an HTTP fingerprint,
// but it does not by itself prove that a takeover is exploitable.
package validation

type State string

const (
	Available   State = "available"
	Unavailable State = "unavailable"
	Unknown     State = "unknown"
	Unsupported State = "unsupported"
)

type Result struct {
	Provider string `json:"provider"`
	State    State  `json:"state"`
	Target   string `json:"target,omitempty"`
	Reason   string `json:"reason,omitempty"`
}
