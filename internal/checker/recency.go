package checker

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/apoorv-kulkarni/vigiles/internal/scanner"
	"github.com/apoorv-kulkarni/vigiles/internal/signal"
)

const (
	recentThreshold    = 7 * 24 * time.Hour
	recencyHTTPTimeout = 5 * time.Second
)

// RecencyChecker checks if package versions were published very recently.
// A version published in the last 7 days is flagged as a trust signal.
//
// Uses an in-memory cache keyed by package+version so repeated lookups
// (e.g., same package in multiple venvs) don't re-hit the network.
// Individual request failures are non-fatal — the signal is simply omitted.
type RecencyChecker struct {
	client *http.Client
	Now    func() time.Time

	mu    sync.Mutex
	cache map[string]*recencyCacheEntry
}

type recencyCacheEntry struct {
	uploadTime time.Time
	found      bool
}

func NewRecencyChecker() *RecencyChecker {
	return &RecencyChecker{
		client: &http.Client{Timeout: recencyHTTPTimeout},
		Now:    time.Now,
		cache:  map[string]*recencyCacheEntry{},
	}
}

// Stats tracks per-check timing for progress reporting.
type RecencyStats struct {
	Checked  int
	Signals  int
	Skipped  int
	Errors   int
	Duration time.Duration
}

// CheckWithStats is like Check but also returns timing information.
func (c *RecencyChecker) CheckWithStats(packages []scanner.Package) ([]signal.Signal, RecencyStats) {
	start := time.Now()
	var stats RecencyStats
	var signals []signal.Signal

	for _, pkg := range packages {
		if pkg.Ecosystem != "pip" {
			continue
		}
		stats.Checked++
		sig, err := c.checkPyPI(pkg)
		if err != nil {
			stats.Errors++
			continue
		}
		if sig != nil {
			stats.Signals++
			signals = append(signals, *sig)
		}
	}

	stats.Duration = time.Since(start)
	stats.Skipped = stats.Errors
	return signals, stats
}

// Check examines PyPI packages for recently published versions.
func (c *RecencyChecker) Check(packages []scanner.Package) []signal.Signal {
	sigs, _ := c.CheckWithStats(packages)
	return sigs
}

// CheckVersion checks a single package/version. Exported for diff command.
func (c *RecencyChecker) CheckVersion(name, version, ecosystem string) *signal.Signal {
	if ecosystem != "pip" {
		return nil
	}
	sig, _ := c.checkPyPI(scanner.Package{Name: name, Version: version, Ecosystem: ecosystem})
	return sig
}

func (c *RecencyChecker) checkPyPI(pkg scanner.Package) (*signal.Signal, error) {
	cacheKey := pkg.Name + "@" + pkg.Version

	c.mu.Lock()
	entry, cached := c.cache[cacheKey]
	c.mu.Unlock()

	if !cached {
		uploadTime, found, err := c.fetchUploadTime(pkg.Name, pkg.Version)
		if err != nil {
			return nil, err
		}
		entry = &recencyCacheEntry{uploadTime: uploadTime, found: found}
		c.mu.Lock()
		c.cache[cacheKey] = entry
		c.mu.Unlock()
	}

	if !entry.found {
		return nil, nil
	}

	age := c.Now().Sub(entry.uploadTime)
	if age < recentThreshold {
		return &signal.Signal{
			Package: pkg.Name, Version: pkg.Version, Ecosystem: pkg.Ecosystem,
			Type: "trust-signal", Severity: "info",
			ID:      "VIGILES-RECENTLY-PUBLISHED",
			Summary: fmt.Sprintf("Version published %s ago", formatDuration(age)),
			Details: fmt.Sprintf("Uploaded to PyPI at %s, less than 7 days ago. Recently published versions have had less community review.",
				entry.uploadTime.Format(time.RFC3339)),
		}, nil
	}
	return nil, nil
}

func (c *RecencyChecker) fetchUploadTime(name, version string) (time.Time, bool, error) {
	url := fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", name, version)
	resp, err := c.client.Get(url)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("PyPI request failed for %s: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Package or version not found — not an error, just no data
		return time.Time{}, false, nil
	}

	var data pypiVersionResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return time.Time{}, false, nil
	}

	t := extractUploadTime(data)
	return t, !t.IsZero(), nil
}

func extractUploadTime(data pypiVersionResponse) time.Time {
	for _, f := range data.Urls {
		if f.UploadTimeISO != "" {
			if t, err := time.Parse(time.RFC3339, f.UploadTimeISO); err == nil {
				return t
			}
		}
		if f.UploadTime != "" {
			if t, err := time.Parse("2006-01-02T15:04:05", f.UploadTime); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}

func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	if hours < 1 {
		return "< 1 hour"
	}
	if hours < 24 {
		return fmt.Sprintf("%d hours", hours)
	}
	return fmt.Sprintf("%d days", hours/24)
}

type pypiVersionResponse struct {
	Urls []pypiFile `json:"urls"`
}

type pypiFile struct {
	UploadTimeISO string `json:"upload_time_iso_8601"`
	UploadTime    string `json:"upload_time"`
}
