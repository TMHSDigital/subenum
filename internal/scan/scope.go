package scan

import (
	"fmt"
	"strings"

	"github.com/TMHSDigital/subenum/internal/validate"
)

// scope holds -exclude patterns (#87). An exact pattern excludes that one
// name; "*.parent" excludes every name below parent, but not parent itself,
// which is how bug-bounty programs usually write out-of-scope hosts.
type scope struct {
	exact    map[string]struct{}
	suffixes []string // "*.x" patterns, stored as "x"
}

func normalizePattern(p string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p), "."))
}

// ValidateExcludes checks that every pattern is a domain or *.domain.
func ValidateExcludes(patterns []string) error {
	for _, p := range patterns {
		n := normalizePattern(p)
		if err := validate.Domain(strings.TrimPrefix(n, "*.")); err != nil {
			return fmt.Errorf("invalid -exclude pattern %q: %w", p, err)
		}
	}
	return nil
}

func newScope(patterns []string) *scope {
	s := &scope{exact: make(map[string]struct{})}
	for _, p := range patterns {
		n := normalizePattern(p)
		if suffix, ok := strings.CutPrefix(n, "*."); ok {
			s.suffixes = append(s.suffixes, suffix)
		} else if n != "" {
			s.exact[n] = struct{}{}
		}
	}
	return s
}

// excluded reports whether name is out of scope.
func (s *scope) excluded(name string) bool {
	if s == nil {
		return false
	}
	name = strings.ToLower(name)
	if _, ok := s.exact[name]; ok {
		return true
	}
	return s.subtreeExcluded(parentOf(name))
}

// subtreeExcluded reports whether every name below parent is out of scope,
// so expanding parent would only produce excluded candidates.
func (s *scope) subtreeExcluded(parent string) bool {
	if s == nil {
		return false
	}
	parent = strings.ToLower(parent)
	for _, suffix := range s.suffixes {
		if parent == suffix || strings.HasSuffix(parent, "."+suffix) {
			return true
		}
	}
	return false
}

func parentOf(name string) string {
	if i := strings.IndexByte(name, '.'); i >= 0 {
		return name[i+1:]
	}
	return ""
}

// IsExcluded reports whether name is out of scope under the -exclude
// patterns, using the same rules as a scan.
func IsExcluded(patterns []string, name string) bool {
	return newScope(patterns).excluded(name)
}
