// Package rules contains Abigail's audited, versioned default rule set.
package rules

import _ "embed"

//go:embed providers.json
var Default []byte
