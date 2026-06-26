# Lab 3 — Submission

## Task 1: SSH Commit Signing

### Local configuration
- `git config --global gpg.format` → `ssh`
- `git config --global user.signingkey` → `/home/stoat/.ssh/id_ed25519.pub`
- `git config --global commit.gpgsign` → `true`

### Local verification
Output of `git log --show-signature -1`:

```
commit 01a30ad8b01f03a776e31d2e98da021db2ac01e1 (HEAD -> feature/lab3, origin/feature/lab3)
Good "git" signature for m.panchenko@innopolis.university with ED25519 key SHA256:<redacted>
Author: Matvei Panchenko <m.panchenko@innopolis.university>
Date:   Fri Jun 26 08:33:50 2026 +0300

    feat(lab3): SSH signing + gitleaks pre-commit + history rewrite practice
```

### GitHub verification
- Direct link to the signed commit on GitHub: https://github.com/uSs3ewa/DevSecOps-Intro/commit/01a30ad8b01f03a776e31d2e98da021db2ac01e1
- Screenshot of the Verified badge: attached in the PR under **Artifacts & Screenshots**

### One-paragraph reflection (2-3 sentences)
In a real team, a forged-author commit (STRIDE-R / Repudiation) lets an attacker land malicious code while blaming someone else—or deny writing their own changes during an incident. Signed commits tie authorship to a cryptographic identity, so `git blame` and audit trails become trustworthy. The green **Verified** badge on GitHub makes impersonation visible immediately instead of discovered weeks later during forensics.

---

## Task 2: Pre-commit + gitleaks

### `.pre-commit-config.yaml` (paste the full content)

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.0
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
```

### `pre-commit install` output

```
pre-commit installed at .git/hooks/pre-commit
```

### The blocked commit
Output of the `git commit` that gitleaks blocked (the failing hook output):

```
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

Finding:     GH_PAT=REDACTED
Secret:      REDACTED
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        2
Fingerprint: submissions/leak-attempt.txt:github-pat:2

8:30AM INF 0 commits scanned.
8:30AM INF scanned ~101 bytes (101 bytes) in 29ms
8:30AM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed
```

### Tune-out exercise
1. **Inline allowlist** — `[allowlist]` in `.gitleaks.toml` for a specific fingerprint or regex is OK when the match is a known false positive (documented example strings, test fixtures) and the allowlist is as narrow as possible (single line/fingerprint, not whole rule). It is risky if used to silence real secrets “temporarily.”
2. **Path exclusion** — `paths: [docs/]` excludes everything under `docs/` from scanning. This is risky because documentation folders often accumulate copied `.env` snippets, sample configs, or pasted tokens; attackers also know “docs” is a common blind spot.

---

## Bonus: History Rewrite

### Before

```
8ce5a5e docs: add usage notes
771e7c8 feat: empty log
e45559a feat: add config
de5364e init
```

Output of `git log -p | grep -c 'ghp_'`: **2**

### After

```
d0e9154 docs: add usage notes
d54f5dc feat: empty log
a7b6c18 feat: add config
de5364e init
```

Output of `git log -p | grep -c 'ghp_'`: **0**  
Output of `git log -p | grep -c 'REDACTED'`: **2**

### The two-step pattern in real life
1. `git filter-repo --replace-text replacements.txt` — rewrite local history to remove the secret from all commits.
2. **Rotate/revoke the exposed secret immediately** — history rewrite only removes the leak from git; anyone who already cloned or scraped the old commits may still have the credential. Rotation is mandatory remediation; rewrite alone is cleanup.

### Two real-world gotchas you discovered (2 sentences each)
1. **Passphrase-protected signing key blocks commits in CI/automation:** With `commit.gpgsign=true`, `git commit` failed until the SSH key was available via `ssh-agent` (`ssh_askpass` was missing). For throwaway sandboxes (bonus repo), disabling signing locally (`git config commit.gpgsign false`) avoided blocking unrelated history-rewrite practice.
2. **`git filter-repo` rewrites commit SHAs:** After `--replace-text`, every affected commit got a new hash (`8ce5a5e` → `d0e9154`), so any existing clones/remotes need a force-push and collaborators must re-clone or hard-reset—treat it as a breaking history change.
