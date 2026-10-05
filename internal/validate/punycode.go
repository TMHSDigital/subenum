package validate

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// RFC 3492 Punycode parameters.
const (
	pcBase        = 36
	pcTMin        = 1
	pcTMax        = 26
	pcSkew        = 38
	pcDamp        = 700
	pcInitialBias = 72
	pcInitialN    = 128
)

// toASCII converts a lowercased domain to its ASCII (A-label) form: every
// label with non-ASCII characters becomes "xn--" plus its Punycode encoding.
// It implements only the RFC 3492 encoder, not full UTS #46 mapping, which
// covers domains typed in their usual lowercase NFC form (bücher.de) without
// pulling in golang.org/x/net/idna.
func toASCII(domain string) (string, error) {
	labels := strings.Split(domain, ".")
	for i, label := range labels {
		if isASCII(label) {
			continue
		}
		if !utf8.ValidString(label) {
			return "", fmt.Errorf("label %q is not valid UTF-8", label)
		}
		enc, err := punycodeEncode(label)
		if err != nil {
			return "", err
		}
		labels[i] = "xn--" + enc
	}
	return strings.Join(labels, "."), nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// punycodeEncode is the RFC 3492 section 6.3 encoding procedure.
func punycodeEncode(input string) (string, error) {
	runes := []rune(input)
	var out strings.Builder
	for _, r := range runes {
		if r < utf8.RuneSelf {
			out.WriteRune(r)
		}
	}
	basic := out.Len()
	handled := basic
	if basic > 0 {
		out.WriteByte('-')
	}

	n, delta, bias := rune(pcInitialN), 0, pcInitialBias
	for handled < len(runes) {
		// The smallest code point not yet handled.
		m := rune(utf8.MaxRune)
		for _, r := range runes {
			if r >= n && r < m {
				m = r
			}
		}
		if int(m-n) > (1<<31-1-delta)/(handled+1) {
			return "", fmt.Errorf("punycode overflow encoding %q", input)
		}
		delta += int(m-n) * (handled + 1)
		n = m
		for _, r := range runes {
			if r < n {
				delta++
			}
			if r != n {
				continue
			}
			q := delta
			for k := pcBase; ; k += pcBase {
				t := k - bias
				switch {
				case t < pcTMin:
					t = pcTMin
				case t > pcTMax:
					t = pcTMax
				}
				if q < t {
					break
				}
				out.WriteByte(pcDigit(t + (q-t)%(pcBase-t)))
				q = (q - t) / (pcBase - t)
			}
			out.WriteByte(pcDigit(q))
			bias = pcAdapt(delta, handled+1, handled == basic)
			delta = 0
			handled++
		}
		delta++
		n++
	}
	return out.String(), nil
}

// pcDigits maps a Punycode digit value (0-35) to its character.
const pcDigits = "abcdefghijklmnopqrstuvwxyz0123456789"

func pcDigit(d int) byte { return pcDigits[d] }

func pcAdapt(delta, numPoints int, first bool) int {
	if first {
		delta /= pcDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((pcBase-pcTMin)*pcTMax)/2 {
		delta /= pcBase - pcTMin
		k += pcBase
	}
	return k + (pcBase-pcTMin+1)*delta/(delta+pcSkew)
}
