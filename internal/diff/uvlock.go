package diff

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const uvLockKeyPrefix = "\x00uv-lock\x00"

var (
	uvSchemaVersion = regexp.MustCompile(`^version\s*=\s*([0-9]+)\s*(?:#.*)?$`)
	uvNameField     = regexp.MustCompile(`^name\s*=\s*"([^"]+)"\s*(?:#.*)?$`)
	uvVersionField  = regexp.MustCompile(`^version\s*=\s*"([^"]+)"\s*(?:#.*)?$`)
	uvRegistryField = regexp.MustCompile(`registry\s*=\s*"([^"]+)"`)
	uvLocalSource   = regexp.MustCompile(`(?:editable|virtual)\s*=`)
)

type uvLockPackage struct {
	name    string
	version string
	source  string
	line    int
}

func parseUVLock(data []byte) (map[string]string, error) {
	deps := map[string]string{}
	lines := strings.Split(string(data), "\n")
	schema := 0
	sawPackage := false
	inPackageTop := false
	var current *uvLockPackage

	flush := func() error {
		if current == nil {
			return nil
		}
		if current.name == "" {
			return fmt.Errorf("uv.lock package at line %d is missing name", current.line)
		}
		if current.source == "" {
			return fmt.Errorf("uv.lock package %q is missing source", current.name)
		}
		if uvLocalSource.MatchString(current.source) {
			current = nil
			return nil
		}
		match := uvRegistryField.FindStringSubmatch(current.source)
		if len(match) != 2 {
			return fmt.Errorf("uv.lock package %q uses an unsupported source", current.name)
		}
		registry, err := url.Parse(match[1])
		if err != nil || registry.Scheme != "https" || registry.Host != "pypi.org" ||
			strings.TrimRight(registry.Path, "/") != "/simple" || registry.User != nil {
			return fmt.Errorf("uv.lock package %q uses unsupported registry %q", current.name, match[1])
		}
		if current.version == "" {
			return fmt.Errorf("uv.lock package %q is missing version", current.name)
		}
		deps[uvDependencyKey(current.name, current.version)] = "==" + current.version
		current = nil
		return nil
	}

	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if line == "[[package]]" {
			if err := flush(); err != nil {
				return nil, err
			}
			sawPackage = true
			inPackageTop = true
			current = &uvLockPackage{line: i + 1}
			continue
		}

		if !sawPackage {
			if match := uvSchemaVersion.FindStringSubmatch(line); len(match) == 2 {
				value, err := strconv.Atoi(match[1])
				if err != nil {
					return nil, fmt.Errorf("invalid uv.lock schema version at line %d", i+1)
				}
				schema = value
			}
			continue
		}

		if current == nil {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inPackageTop = false
			continue
		}
		if !inPackageTop {
			continue
		}
		if match := uvNameField.FindStringSubmatch(line); len(match) == 2 {
			current.name = match[1]
			continue
		}
		if match := uvVersionField.FindStringSubmatch(line); len(match) == 2 {
			current.version = match[1]
			continue
		}
		if strings.HasPrefix(line, "source") {
			current.source = line
		}
	}

	if err := flush(); err != nil {
		return nil, err
	}
	if schema == 0 {
		return nil, fmt.Errorf("uv.lock is missing schema version")
	}
	if schema != 1 {
		return nil, fmt.Errorf("unsupported uv.lock schema version %d", schema)
	}
	return deps, nil
}

func uvDependencyKey(name, version string) string {
	return uvLockKeyPrefix + strings.ToLower(strings.TrimSpace(name)) + "\x00" + version
}

func dependencyDisplayName(key string) string {
	if !strings.HasPrefix(key, uvLockKeyPrefix) {
		return key
	}
	rest := strings.TrimPrefix(key, uvLockKeyPrefix)
	if idx := strings.IndexByte(rest, 0); idx >= 0 {
		return rest[:idx]
	}
	return rest
}
