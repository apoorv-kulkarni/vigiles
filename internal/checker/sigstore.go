// sigstore.go inspects PyPI release metadata for PEP 740-style attestation/provenance fields.
package checker

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

type SigstoreChecker struct {
	client *http.Client
}

func NewSigstoreChecker() *SigstoreChecker {
	return &SigstoreChecker{client: &http.Client{Timeout: 5 * time.Second}}
}

func (c *SigstoreChecker) Check(packages []scanner.Package) []signal.Signal {
	if c == nil || c.client == nil {
		return nil
	}
	var out []signal.Signal
	checked := 0
	for _, pkg := range packages {
		if checked >= 30 {
			break
		}
		if pkg.Ecosystem != "pip" || !pkg.Direct || pkg.Version == "" {
			continue
		}
		checked++
		hasAttestation := c.hasPEP740Metadata(pkg.Name, pkg.Version)
		if hasAttestation {
			out = append(out, signal.Signal{
				Package:   pkg.Name,
				Version:   pkg.Version,
				Ecosystem: "pip",
				Type:      "trust-signal",
				Severity:  "info",
				ID:        "VIGILES-PEP740-ATTESTED",
				Summary:   "PyPI release includes attestation/provenance metadata",
				Details:   "Package release metadata indicates PEP 740-style provenance fields.",
			})
			continue
		}
		out = append(out, signal.Signal{
			Package:   pkg.Name,
			Version:   pkg.Version,
			Ecosystem: "pip",
			Type:      "trust-signal",
			Severity:  "low",
			ID:        "VIGILES-PEP740-NO-ATTESTATION",
			Summary:   "No PEP 740 attestation metadata found for this release",
			Details:   "Could not find provenance/attestation fields in PyPI release file metadata.",
		})
	}
	return out
}

func (c *SigstoreChecker) hasPEP740Metadata(name, version string) bool {
	u := fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", name, version)
	resp, err := c.client.Get(u)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return false
	}
	defer resp.Body.Close()

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false
	}

	urls, _ := payload["urls"].([]any)
	for _, u := range urls {
		file, ok := u.(map[string]any)
		if !ok {
			continue
		}
		for k, v := range file {
			lk := strings.ToLower(strings.TrimSpace(k))
			if lk == "provenance" || lk == "attestations" || lk == "sigstore" {
				if v != nil {
					return true
				}
			}
		}
	}
	return false
}
