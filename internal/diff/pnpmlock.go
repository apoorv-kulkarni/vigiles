package diff

import (
	"fmt"
	"regexp"
	"strings"
)

const pnpmLockKeyPrefix = "\x00pnpm-lock\x00"

var (
	pnpmLockVersion = regexp.MustCompile(`^lockfileVersion:\s*['"]?([^'"]+)['"]?\s*(?:#.*)?package diff

import (
	"fmt"
	"regexp"
	"strings"
)

const pnpmLockKeyPrefix = "\x00pnpm-lock\x00"

)
	pnpmIntegrity   = regexp.MustCompile(`integrity:\s*['"]?([^,'"}[:space:]]+)`)
)

type pnpmLockPackage struct {
	name       string
	version    string
	resolution string
	line       int
}

func parsePNPMLock(data []byte) (map[string]string, error) {
	deps := map[string]string{}
	resolutions := map[string]string{}
	lines := strings.Split(string(data), "\n")
	seenVersion := false
	inPackages := false
	var current *pnpmLockPackage
	inResolution := false

	flush := func() error {
		if current == nil {
			return nil
		}
		if current.name == "" || current.version == "" {
			return fmt.Errorf("pnpm-lock.yaml package at line %d has an invalid package key", current.line)
		}
		if current.resolution == "" {
			return fmt.Errorf("pnpm-lock.yaml package %s@%s is missing resolution metadata", current.name, current.version)
		}
		integrity, err := validatePNPMResolution(current.resolution)
		if err != nil {
			return fmt.Errorf("pnpm-lock.yaml package %s@%s: %w", current.name, current.version, err)
		}
		key := pnpmDependencyKey(current.name, current.version, integrity)
		if prior, ok := resolutions[key]; ok && prior != current.resolution {
			return fmt.Errorf("pnpm-lock.yaml package %s@%s has conflicting resolution metadata", current.name, current.version)
		}
		resolutions[key] = current.resolution
		deps[key] = current.version
		current = nil
		inResolution = false
		return nil
	}

	for i, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || trimmed == "---" {
			continue
		}

		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		if indent == 0 {
			switch {
			case trimmed == "patchedDependencies:":
				return nil, fmt.Errorf("pnpm-lock.yaml patchedDependencies are not covered")
			case strings.HasPrefix(trimmed, "pnpmfileChecksum:"):
				return nil, fmt.Errorf("pnpm-lock.yaml pnpmfile hooks are not covered")
			case strings.HasPrefix(trimmed, "untrackedPnpmfileReadPackageHook:"):
				return nil, fmt.Errorf("pnpm-lock.yaml untracked pnpmfile hooks are not covered")
			}
			if match := pnpmLockVersion.FindStringSubmatch(trimmed); len(match) == 2 {
				if match[1] != "9.0" {
					return nil, fmt.Errorf("unsupported pnpm lockfile version %q", match[1])
				}
				seenVersion = true
			}
			if trimmed == "packages:" {
				if err := flush(); err != nil {
					return nil, err
				}
				inPackages = true
				continue
			}
			if inPackages {
				if err := flush(); err != nil {
					return nil, err
				}
				inPackages = false
			}
			continue
		}

		if !inPackages {
			continue
		}

		if indent == 2 && strings.HasSuffix(trimmed, ":") {
			if err := flush(); err != nil {
				return nil, err
			}
			key, err := parsePNPMPackageYAMLKey(strings.TrimSuffix(trimmed, ":"))
			if err != nil {
				return nil, fmt.Errorf("pnpm-lock.yaml line %d: %w", i+1, err)
			}
			name, version, err := splitPNPMPackageKey(key)
			if err != nil {
				return nil, fmt.Errorf("pnpm-lock.yaml line %d: %w", i+1, err)
			}
			current = &pnpmLockPackage{name: name, version: version, line: i + 1}
			continue
		}

		if current == nil {
			continue
		}

		if indent == 4 && strings.HasPrefix(trimmed, "resolution:") {
			value := strings.TrimSpace(strings.TrimPrefix(trimmed, "resolution:"))
			if value == "" {
				current.resolution = "resolution:"
				inResolution = true
			} else {
				current.resolution = value
				inResolution = false
			}
			continue
		}

		if inResolution {
			if indent <= 4 {
				inResolution = false
			} else {
				current.resolution += " " + trimmed
				continue
			}
		}
	}

	if err := flush(); err != nil {
		return nil, err
	}
	if !seenVersion {
		return nil, fmt.Errorf("pnpm-lock.yaml is missing lockfileVersion")
	}
	return deps, nil
}

func parsePNPMPackageYAMLKey(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) >= 2 && raw[0] == '\'' && raw[len(raw)-1] == '\'' {
		return strings.ReplaceAll(raw[1:len(raw)-1], "''", "'"), nil
	}
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		value := raw[1 : len(raw)-1]
		value = strings.ReplaceAll(value, "\\"", """)
		return value, nil
	}
	if strings.Contains(raw, ": ") {
		return "", fmt.Errorf("unsupported YAML package key %q", raw)
	}
	return raw, nil
}

func splitPNPMPackageKey(key string) (string, string, error) {
	base := key
	if idx := strings.Index(base, "("); idx >= 0 {
		base = base[:idx]
	}
	sep := strings.LastIndex(base, "@")
	if sep <= 0 || sep == len(base)-1 {
		return "", "", fmt.Errorf("unsupported pnpm package key %q", key)
	}
	name, version := base[:sep], base[sep+1:]
	if strings.HasPrefix(name, "@") && !strings.Contains(name, "/") {
		return "", "", fmt.Errorf("unsupported pnpm scoped package key %q", key)
	}
	if !npmExactVersion.MatchString(version) {
		return "", "", fmt.Errorf("pnpm package %q does not use an exact semver version", key)
	}
	return name, version, nil
}

func validatePNPMResolution(resolution string) (string, error) {
	lower := strings.ToLower(resolution)
	for _, unsupported := range []string{
		"tarball:", "type:", "repo:", "directory:", "url:", "bin:", "archive:", "variants:",
	} {
		if strings.Contains(lower, unsupported) {
			return "", fmt.Errorf("unsupported package source in resolution metadata")
		}
	}
	match := pnpmIntegrity.FindStringSubmatch(resolution)
	if len(match) != 2 {
		return "", fmt.Errorf("resolution does not contain package integrity")
	}
	return match[1], nil
}

func pnpmDependencyKey(name, version, integrity string) string {
	return pnpmLockKeyPrefix + strings.ToLower(strings.TrimSpace(name)) + "\x00" + version + "\x00" + integrity
}

func pnpmDependencyIdentity(key string) (string, string, bool) {
	if !strings.HasPrefix(key, pnpmLockKeyPrefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(key, pnpmLockKeyPrefix)
	parts := strings.SplitN(rest, "\x00", 3)
	if len(parts) != 3 {
		return "", "", false
	}
	return parts[0] + "\x00" + parts[1], parts[1], true
}
