# LiteLLM March 2026 replay

This case study replays the security boundaries Vigiles can evaluate around the
March 24, 2026 LiteLLM supply-chain incident without preserving or executing the
malware.

The repository fixtures are deliberately inert. They contain no credential
collection, network exfiltration, persistence setup, encrypted payload, or
lateral-movement code.

## Incident facts used by the replay

PyPI's incident report says malicious LiteLLM releases were published after
publisher credentials were exposed through an exploited Trivy dependency. The
malware ran on install, harvested credentials and sensitive files, and
exfiltrated them.

LiteLLM's public incident thread identifies versions `1.82.7` and `1.82.8` as
compromised. It reports that `1.82.8` added `litellm_init.pth`, which caused the
payload to run on Python startup without requiring an explicit LiteLLM import.

Snyk reports that the malicious releases were available for approximately three
hours before PyPI quarantine. That duration is useful context, but it is not a
Vigiles detection primitive.

Sources:

- PyPI incident report: https://blog.pypi.org/posts/2026-04-02-incident-report-litellm-telnyx-supply-chain-attack/
- LiteLLM incident thread: https://github.com/BerriAI/litellm/issues/24518
- Snyk timeline: https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/

## Replay 1: before installation

The fixture models this pinned dependency change:

```text
litellm==1.82.6
        ↓
litellm==1.82.8
```

The important property is that LiteLLM was already trusted and already present.
This is not a new-package or typosquat scenario.

Vigiles now applies its PyPI recency check to an exactly pinned **upgrade** as
well as to a newly introduced dependency. The replay injects deterministic
registry-freshness metadata and asserts that the candidate upgrade receives
`VIGILES-RECENTLY-PUBLISHED`.

That signal is a review signal, not proof that the package is malicious. At the
time of an incident it can still provide a useful reason to hold a just-published
upgrade before executing package installation.

Run the deterministic replay with:

```sh
go test ./internal/diff -run LiteLLMReplayPreInstall
```

No package is downloaded or executed by this test.

## Replay 2: after installation

Version `1.82.8` used a Python `.pth` startup hook. The replay fixture contains
only a harmless marker command with the same executable-import shape.

The test copies that fixture into a temporary fake site-packages directory,
points Vigiles at a stub interpreter that reports the directory, and asserts a
critical `VIGILES-MALICIOUS-PTH` finding:

```sh
go test ./internal/checker -run LiteLLMReplayPostInstall
```

The stub interpreter never executes the fixture.

## What this proves, and what it does not

The replay exercises two independent boundaries:

1. **Before install:** a newly published pinned upgrade can be held for review.
2. **After install:** a suspicious executable `.pth` startup hook can be
   detected in the environment.

It does **not** prove that Vigiles can identify the malicious contents of a wheel
from a requirements-file diff. A dependency manifest contains the package name
and version, not the wheel contents.

A stronger future pre-execution boundary would download the candidate artifact
without importing or installing it, verify its expected registry/artifact
identity, and statically inspect wheel contents for executable `.pth` files and
other high-risk install-time behavior. That would move the payload-specific
signal to the pre-install side of the boundary.
