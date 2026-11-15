// subenum - A Go-based CLI tool for subdomain enumeration.
// Copyright (C) 2026 TM Hospitality Strategies
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
// For authorized use only. Only scan domains you own or have explicit
// written permission to test.

// Command subenum enumerates subdomains by DNS brute-forcing a wordlist
// against one or more domains, with wildcard filtering, rate limiting, a
// simulation mode and an interactive terminal UI (-tui). The command itself
// lives in internal/cli; this file stays at the module root so that
// go install github.com/TMHSDigital/subenum@latest keeps working.
package main

import (
	"os"

	"github.com/TMHSDigital/subenum/internal/cli"
)

// Version is the release identifier. Makefile, CI and the Dockerfile set it
// with -ldflags "-X main.Version=$(git describe --tags --dirty)".
var Version = ""

func main() {
	os.Exit(cli.Main(Version))
}
