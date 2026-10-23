package scanner

// Policy decides whether a finding is reported.
//
// It is the seam where suppression and noise control plug in. The
// scanner calls it for every finding; a nil Policy reports everything.
//
// Implementations must be safe for concurrent use: the scanner calls
// Policy from several worker goroutines.
type Policy interface {
	// Suppress reports whether the finding should be dropped.
	Suppress(f Finding) bool

	// Severity returns the severity the finding should be reported with,
	// after any remapping. An empty string means "leave it alone".
	Severity(f Finding) string
}

// PolicyFuncs builds a Policy from plain functions. It is the simplest
// way to configure one inline, and is what the config layer uses.
type PolicyFuncs struct {
	SuppressFn func(Finding) bool
	SeverityFn func(Finding) string
}

// Suppress implements Policy.
func (p PolicyFuncs) Suppress(f Finding) bool {
	if p.SuppressFn == nil {
		return false
	}
	return p.SuppressFn(f)
}

// Severity implements Policy.
func (p PolicyFuncs) Severity(f Finding) string {
	if p.SeverityFn == nil {
		return ""
	}
	return p.SeverityFn(f)
}

// NoPolicy is a Policy that reports everything unchanged.
var NoPolicy Policy = PolicyFuncs{}
