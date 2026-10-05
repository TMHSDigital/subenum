// Package data holds files embedded in subenum: the default wordlist, shared
// by the CLI and the pkg/subenum library.
package data

import _ "embed"

// Subdomains5k is the bundled default wordlist: the 5,000 most common
// subdomain labels from SecLists' subdomains-top1million-5000.txt (MIT; the
// license notice is kept in the file's header), one per line (#63).
//
//go:embed subdomains-5k.txt
var Subdomains5k string
