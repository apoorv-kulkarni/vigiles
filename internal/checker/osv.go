package checker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

const (
	osvBatchURL = "https://api.osv.dev/v1/querybatch"
	osvVulnURL  = "https://api.osv.dev/v1/vulns/"
	batchSize   = 100
	httpTimeout = 30 * time.Second

	// hydrateWorkers bounds concurrent detail lookups so a large result set
	// doesn't open hundreds of sockets against the OSV API at once.
	hydrateWorkers = 8

	// maxQueryPages bounds querybatch pagination so a pathological result set
	// cannot loop indefinitely.
	maxQueryPages = 20
)

type OSVChecker struct {
	client *http.Client
}

func NewOSVChecker() *OSVChecker {
	return &OSVChecker{client: &http.Client{Timeout: httpTimeout}}
}

// vulnRef pairs a package with one vulnerability ID returned by querybatch.
type vulnRef struct {
	pkg scanner.Package
	id  string
}

func (c *OSVChecker) Check(packages []scanner.Package) ([]signal.Signal, error) {
	// Filter out ecosystems we can't meaningfully query.
	queryable := make([]scanner.Package, 0, len(packages))
	for _, pkg := range packages {
		if mapEcosystem(pkg.Ecosystem) != "" {
			queryable = append(queryable, pkg)
		}
	}

	var refs []vulnRef
	var batchErrs []string
	for i := 0; i < len(queryable); i += batchSize {
		end := i + batchSize
		if end > len(queryable) {
			end = len(queryable)
		}
		batch, err := c.checkBatch(queryable[i:end])
		if err != nil {
			batchErrs = append(batchErrs, fmt.Sprintf("batch %d-%d: %v", i, end, err))
			continue
		}
		refs = append(refs, batch...)
	}

	signals := c.signalsFor(refs)
	if len(batchErrs) > 0 {
		return signals, fmt.Errorf("%d batch(es) failed (partial results returned): %s",
			len(batchErrs), strings.Join(batchErrs, "; "))
	}
	return signals, nil
}

// checkBatch resolves one batch of packages to (package, vulnerability ID)
// pairs. querybatch answers with abbreviated entries carrying only `id` and
// `modified`, so the full records are fetched separately by hydrate.
func (c *OSVChecker) checkBatch(packages []scanner.Package) ([]vulnRef, error) {
	queries := make([]osvQuery, len(packages))
	for i, pkg := range packages {
		queries[i] = osvQuery{
			Package: osvPackage{Name: pkg.Name, Ecosystem: mapEcosystem(pkg.Ecosystem)},
			Version: pkg.Version,
		}
	}

	// OSV paginates per query, so each round re-sends only the queries that
	// reported more results, carrying the page token OSV handed back.
	pending := make([]int, len(queries))
	for i := range pending {
		pending[i] = i
	}

	var refs []vulnRef
	for page := 0; page < maxQueryPages && len(pending) > 0; page++ {
		req := osvBatchRequest{Queries: make([]osvQuery, len(pending))}
		for i, qi := range pending {
			req.Queries[i] = queries[qi]
		}

		resp, err := c.postBatch(req)
		if err != nil {
			return nil, err
		}
		if len(resp.Results) != len(req.Queries) {
			return nil, fmt.Errorf("OSV returned %d results for %d queries", len(resp.Results), len(req.Queries))
		}

		var next []int
		for i, result := range resp.Results {
			qi := pending[i]
			for _, vuln := range result.Vulns {
				refs = append(refs, vulnRef{pkg: packages[qi], id: vuln.ID})
			}
			if result.NextPageToken != "" {
				queries[qi].PageToken = result.NextPageToken
				next = append(next, qi)
			}
		}
		pending = next
	}
	return refs, nil
}

func (c *OSVChecker) postBatch(req osvBatchRequest) (*osvBatchResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Post(osvBatchURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("OSV API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var batchResp osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("parsing OSV response: %w", err)
	}
	return &batchResp, nil
}

// signalsFor turns querybatch references into signals, fetching the full record
// for each distinct vulnerability ID first. Without that fetch every finding
// would carry an empty summary, no aliases, no fixed versions, and an unknown
// severity, because querybatch omits all of them.
func (c *OSVChecker) signalsFor(refs []vulnRef) []signal.Signal {
	if len(refs) == 0 {
		return nil
	}

	details := c.hydrate(distinctIDs(refs))

	signals := make([]signal.Signal, 0, len(refs))
	for _, ref := range refs {
		vuln, ok := details[ref.id]
		if !ok {
			// The detail lookup failed. Report the finding with what
			// querybatch gave us rather than dropping a real vulnerability.
			vuln = osvVuln{ID: ref.id}
		}
		signals = append(signals, signal.Signal{
			Package:     ref.pkg.Name,
			Version:     ref.pkg.Version,
			Ecosystem:   ref.pkg.Ecosystem,
			Type:        "vulnerability",
			Severity:    classifySeverity(vuln),
			ID:          ref.id,
			Summary:     summaryFromVuln(vuln),
			Details:     fmt.Sprintf("https://osv.dev/vulnerability/%s", ref.id),
			Remediation: remediationFromVuln(ref.pkg.Name, ref.pkg.Ecosystem, vuln),
			Aliases:     vuln.Aliases,
		})
	}
	return signals
}

// hydrate fetches the full record for each vulnerability ID. A failed lookup is
// skipped rather than fatal: degrading one finding's metadata is far better
// than failing the scan or hiding the finding.
func (c *OSVChecker) hydrate(ids []string) map[string]osvVuln {
	out := make(map[string]osvVuln, len(ids))
	var mu sync.Mutex
	var wg sync.WaitGroup

	workers := hydrateWorkers
	if len(ids) < workers {
		workers = len(ids)
	}

	work := make(chan string)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range work {
				vuln, err := c.fetchVuln(id)
				if err != nil {
					continue
				}
				mu.Lock()
				out[id] = vuln
				mu.Unlock()
			}
		}()
	}
	for _, id := range ids {
		work <- id
	}
	close(work)
	wg.Wait()

	return out
}

func (c *OSVChecker) fetchVuln(id string) (osvVuln, error) {
	resp, err := c.client.Get(osvVulnURL + url.PathEscape(id))
	if err != nil {
		return osvVuln{}, fmt.Errorf("OSV detail request failed for %s: %w", id, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return osvVuln{}, fmt.Errorf("OSV returned %d for %s", resp.StatusCode, id)
	}

	var vuln osvVuln
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return osvVuln{}, fmt.Errorf("parsing OSV record %s: %w", id, err)
	}
	return vuln, nil
}

// distinctIDs returns each vulnerability ID once, preserving first-seen order.
// One advisory commonly affects several installed packages.
func distinctIDs(refs []vulnRef) []string {
	seen := make(map[string]bool, len(refs))
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		if seen[ref.id] {
			continue
		}
		seen[ref.id] = true
		out = append(out, ref.id)
	}
	return out
}

// mapEcosystem returns the OSV ecosystem name, or "" if we can't query it.
// Homebrew has no OSV ecosystem — we skip it rather than producing false negatives.
func mapEcosystem(eco string) string {
	switch eco {
	case "pip":
		return "PyPI"
	case "npm":
		return "npm"
	case "cargo":
		return "crates.io"
	case "gomod":
		return "Go"
	default:
		return ""
	}
}

// summaryFromVuln prefers the one-line summary, falls back to the first line of
// the long description (PYSEC and RUSTSEC records often carry no summary), and
// finally names the ID when the detail lookup failed.
func summaryFromVuln(vuln osvVuln) string {
	if s := strings.TrimSpace(vuln.Summary); s != "" {
		return s
	}
	if d := strings.TrimSpace(vuln.Description); d != "" {
		return truncate(strings.TrimSpace(strings.SplitN(d, "\n", 2)[0]), 200)
	}
	return fmt.Sprintf("%s (no description available from OSV)", vuln.ID)
}

// classifySeverity resolves a qualitative severity from the record. OSV carries
// CVSS severities as vector strings rather than numbers, so the vector is
// scored directly; database_specific.severity is the fallback for records that
// carry no v3 vector, which is how CVSS v4-only advisories are ranked.
func classifySeverity(vuln osvVuln) string {
	for _, sev := range vuln.Severity {
		if score, err := strconv.ParseFloat(strings.TrimSpace(sev.Score), 64); err == nil {
			return scoreToSeverity(score)
		}
	}
	for _, sev := range vuln.Severity {
		if score, ok := cvss3BaseScore(sev.Score); ok {
			return scoreToSeverity(score)
		}
	}
	if s := normalizeQualitativeSeverity(vuln.DatabaseSpecific.Severity); s != "" {
		return s
	}
	return "unknown"
}

// normalizeQualitativeSeverity maps the ratings used by database_specific onto
// our vocabulary. GitHub advisories say MODERATE where CVSS says medium.
func normalizeQualitativeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high", "important":
		return "high"
	case "moderate", "medium":
		return "medium"
	case "low", "negligible":
		return "low"
	default:
		return ""
	}
}

func scoreToSeverity(score float64) string {
	score = math.Round(score*10) / 10
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score >= 0.1:
		return "low"
	default:
		return "info"
	}
}

func remediationFromVuln(pkgName, ecosystem string, vuln osvVuln) string {
	fixed := fixedVersions(vuln)
	if len(fixed) > 0 {
		top := fixed
		if len(top) > 3 {
			top = top[:3]
		}
		return fmt.Sprintf("Upgrade %s to a non-vulnerable version. OSV fixed versions include: %s.",
			pkgName, strings.Join(top, ", "))
	}
	switch ecosystem {
	case "pip":
		return fmt.Sprintf("Upgrade %s to a currently supported release.", pkgName)
	case "npm":
		return fmt.Sprintf("Upgrade %s to a maintained release.", pkgName)
	default:
		return fmt.Sprintf("Upgrade %s to a safer, supported version.", pkgName)
	}
}

func fixedVersions(vuln osvVuln) []string {
	seen := map[string]bool{}
	var out []string
	for _, affected := range vuln.Affected {
		for _, r := range affected.Ranges {
			for _, ev := range r.Events {
				v := strings.TrimSpace(ev.Fixed)
				if v == "" || seen[v] {
					continue
				}
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	sort.Strings(out)
	return out
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}
type osvQuery struct {
	Package   osvPackage `json:"package"`
	Version   string     `json:"version"`
	PageToken string     `json:"page_token,omitempty"`
}
type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}
type osvBatchResponse struct {
	Results []osvResult `json:"results"`
}
type osvResult struct {
	Vulns         []osvVuln `json:"vulns"`
	NextPageToken string    `json:"next_page_token,omitempty"`
}
type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Aliases  []string      `json:"aliases"`
	Severity []osvSeverity `json:"severity"`
	Affected []osvAffected `json:"affected"`
	// Description is OSV's long-form `details` field, not to be confused with
	// the advisory URL Vigiles puts in Signal.Details.
	Description      string              `json:"details"`
	DatabaseSpecific osvDatabaseSpecific `json:"database_specific"`
}
type osvDatabaseSpecific struct {
	Severity string `json:"severity"`
}
type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}
type osvAffected struct {
	Ranges []osvRange `json:"ranges"`
}
type osvRange struct {
	Events []osvEvent `json:"events"`
}
type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}
