// Package labs embeds the lab scenario zones and their wordlist, so subenum
// mcp's lab_scan can serve them from any directory.
package labs

import "embed"

// Files holds every *.zone scenario and words.txt, at the root of the tree.
//
//go:embed *.zone words.txt
var Files embed.FS
