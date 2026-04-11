// provenance.go performs lightweight registry-to-GitHub tag checks for direct pip/npm packages.
package checker

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

type ProvenanceChecker struct {
	client *http.Client
}

func NewProvenanceChecker() *ProvenanceChecker {
	return &ProvenanceChecker{client: &http.Client{Timeout: 5 * time.Second}}
}

func (c *ProvenanceChecker) Check(packages []scanner.Package) []signal.Signal {
	if c == nil || c.client == nil {
		return nil
	}
	var out []signal.Signal
	checked := 0
	for _, pkg := range packages {
		if checked >= 30 {
			break
		}
		if !pkg.Direct || pkg.Version == "" {
			continue
		}
		repo := ""
		switch pkg.Ecosystem {
		case "pip":
			repo = c.findRepoFromPyPI(pkg.Name, pkg.Version)
		case "npm":
			repo = c.findRepoFromNPM(pkg.Name, pkg.Version)
		default:
			continue
		}
		checked++
		if repo == "" {
			continue
		}
		found, err := c.repoHasVersionTag(repo, pkg.Version)
		if err != nil {
			out = append(out, signal.Signal{
				Package:   pkg.Name,
				Version:   pkg.Version,
				Ecosystem: pkg.Ecosystem,
				Type:      "trust-signal",
				Severity:  "info",
				ID:        "VIGILES-PROVENANCE-UNVERIFIABLE",
				Summary:   "Provenance check could not be completed",
				Details:   fmt.Sprintf("Could not fetch tags for repository %s: %v. This is informational — it does not indicate a mismatch.", repo, err),
			})
		} else if !found {
			out = append(out, signal.Signal{
				Package:   pkg.Name,
				Version:   pkg.Version,
				Ecosystem: pkg.Ecosystem,
				Type:      "trust-signal",
				Severity:  "info",
				ID:        "VIGILES-PROVENANCE-TAG-MISMATCH",
				Summary:   "GitHub source tag does not match registry version",
				Details:   fmt.Sprintf("Repository %s does not expose tag %s (or v%s).", repo, pkg.Version, pkg.Version),
			})
		}
	}
	return out
}

func (c *ProvenanceChecker) findRepoFromPyPI(name, version string) string {
	u := fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", name, version)
	resp, err := c.client.Get(u)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	defer resp.Body.Close()
	var payload struct {
		Info struct {
			ProjectURLs map[string]string `json:"project_urls"`
			HomePage    string            `json:"home_page"`
		} `json:"info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return ""
	}
	for _, v := range payload.Info.ProjectURLs {
		if repo := extractGitHubRepo(v); repo != "" {
			return repo
		}
	}
	return extractGitHubRepo(payload.Info.HomePage)
}

func (c *ProvenanceChecker) findRepoFromNPM(name, version string) string {
	u := fmt.Sprintf("https://registry.npmjs.org/%s/%s", name, version)
	resp, err := c.client.Get(u)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	defer resp.Body.Close()
	var payload struct {
		Repository struct {
			URL string `json:"url"`
		} `json:"repository"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return ""
	}
	return extractGitHubRepo(payload.Repository.URL)
}

func (c *ProvenanceChecker) repoHasVersionTag(repo, version string) (bool, error) {
	want := strings.TrimSpace(version)
	wantV := "v" + want

	for page := 1; page <= 5; page++ {
		u := fmt.Sprintf("https://api.github.com/repos/%s/tags?per_page=100&page=%d", repo, page)
		resp, err := c.client.Get(u)
		if err != nil {
			return false, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return false, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
		}
		var tags []struct {
			Name string `json:"name"`
		}
		err = json.NewDecoder(resp.Body).Decode(&tags)
		resp.Body.Close()
		if err != nil {
			return false, err
		}
		for _, t := range tags {
			name := strings.TrimSpace(t.Name)
			if name == want || name == wantV {
				return true, nil
			}
		}
		if len(tags) < 100 {
			return false, nil
		}
	}
	return false, nil
}

func extractGitHubRepo(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	s = strings.TrimPrefix(s, "git+")
	s = strings.TrimSuffix(s, ".git")
	s = strings.ReplaceAll(s, "git@github.com:", "https://github.com/")
	re := regexp.MustCompile(`github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)`) // owner/repo
	m := re.FindStringSubmatch(s)
	if len(m) != 3 {
		return ""
	}
	return m[1] + "/" + m[2]
}
