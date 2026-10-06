package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// SARIF (2.1.0) output for takeover candidates (#129), so findings can be
// uploaded to GitHub code scanning (or any SARIF consumer) and tracked,
// triaged and dismissed there. Only names with a takeover hint are results;
// a run with none writes a valid document with no results.

const sarifHelp = "https://tmhsdigital.github.io/subenum/"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      sarifText      `json:"fullDescription"`
	HelpURI              string         `json:"helpUri"`
	DefaultConfiguration sarifRuleLevel `json:"defaultConfiguration"`
	Properties           sarifRuleProps `json:"properties"`
}

type sarifRuleLevel struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags"`
	SecuritySeverity string   `json:"security-severity"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// takeoverRule maps a takeover marker ("dangling", "provider:heroku",
// "dangling:heroku") to its SARIF rule.
func takeoverRule(marker string) sarifRule {
	kind, provider, _ := strings.Cut(marker, ":")
	r := sarifRule{HelpURI: sarifHelp + "cli.html", Properties: sarifRuleProps{Tags: []string{"security", "subdomain-takeover", "dns"}}}
	switch {
	case kind == "dangling" && provider == "":
		r.ID, r.Name = "subenum/dangling-cname", "DanglingCNAME"
		r.ShortDescription.Text = "CNAME points at a name that does not exist"
		r.FullDescription.Text = "The subdomain is an alias for a name that returns NXDOMAIN. Whoever registers or claims that name may control the subdomain. Remove the record or reclaim the target."
		r.DefaultConfiguration.Level, r.Properties.SecuritySeverity = "error", "7.5"
	case kind == "dangling":
		r.ID, r.Name = "subenum/dangling-cname/"+provider, "DanglingCNAMEAt"+provider
		r.ShortDescription.Text = "CNAME points at an unclaimed " + provider + " name"
		r.FullDescription.Text = "The subdomain is an alias for a " + provider + " name that returns NXDOMAIN. " + provider + " lets anyone claim such names, so this is a likely subdomain takeover. Remove the record or reclaim the resource."
		r.DefaultConfiguration.Level, r.Properties.SecuritySeverity = "error", "8.6"
	default:
		r.ID, r.Name = "subenum/takeover-prone-provider/"+provider, "TakeoverProneProvider"+provider
		r.ShortDescription.Text = "CNAME points at " + provider + ", a takeover-prone service"
		r.FullDescription.Text = "The subdomain is an alias for a " + provider + " resource. It resolves today, but if the resource is deleted while the record stays, anyone can claim it. Keep the record and the resource in the same lifecycle."
		r.DefaultConfiguration.Level, r.Properties.SecuritySeverity = "note", "3.0"
	}
	return r
}

// WriteSARIF writes the takeover candidates among results to path as a
// SARIF 2.1.0 log, atomically. version is the tool version.
func WriteSARIF(path, version string, results []Result) error {
	rules := map[string]sarifRule{}
	var out []sarifResult
	for _, r := range results {
		if r.Takeover == "" {
			continue
		}
		rule := takeoverRule(r.Takeover)
		rules[rule.ID] = rule
		target := ""
		for _, rec := range r.Records {
			if rec.Type == "CNAME" {
				target = strings.TrimSuffix(rec.Value, ".")
			}
		}
		msg := fmt.Sprintf("%s: %s", r.Subdomain, rule.ShortDescription.Text)
		if target != "" {
			msg = fmt.Sprintf("%s is a CNAME for %s. %s.", r.Subdomain, target, rule.ShortDescription.Text)
		}
		sum := sha256.Sum256([]byte(r.Subdomain + "\x00" + r.Takeover))
		out = append(out, sarifResult{
			RuleID:              rule.ID,
			Level:               rule.DefaultConfiguration.Level,
			Message:             sarifText{Text: msg},
			Locations:           []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: r.Subdomain}}}},
			PartialFingerprints: map[string]string{"subenumTakeover/v1": hex.EncodeToString(sum[:16])},
		})
	}
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	driver := sarifDriver{Name: "subenum", Version: version, InformationURI: sarifHelp, Rules: []sarifRule{}}
	for _, id := range ids {
		driver.Rules = append(driver.Rules, rules[id])
	}
	if out == nil {
		out = []sarifResult{}
	}
	doc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{{Tool: sarifTool{Driver: driver}, Results: out}},
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	f, err := CreateFile(path)
	if err != nil {
		return err
	}
	_, werr := f.Write(append(data, '\n'))
	if cerr := f.Close(werr == nil); werr == nil {
		werr = cerr
	}
	return werr
}
