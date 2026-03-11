#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────
# Docs-code sync verification script
# Validates that documentation references to Make targets,
# config variables, and file paths are accurate.
# ─────────────────────────────────────────────

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

DOC_FILES=(
    README.md
    CONTRIBUTING.md
    CHANGELOG.md
    docs/deployment.md
    docs/scenarios.md
    docs/configuration.md
    docs/ctfd-integration.md
    docs/for-professors.md
)

MAKEFILE="Makefile"
ENV_EXAMPLE=".env.example"

ERRORS=0
PASSES=0

# ═══════════════════════════════════════════
# === Make Targets ===
# ═══════════════════════════════════════════
echo "=== Make Targets ==="

# Extract actual targets from Makefile
mapfile -t ACTUAL_TARGETS < <(grep -E '^[a-z][a-z_-]*:' "$MAKEFILE" | sed 's/:.*//')

# Extract referenced targets from docs (backtick-wrapped)
BACKTICK_REFS=""
for file in "${DOC_FILES[@]}"; do
    if [ -f "$file" ]; then
        BACKTICK_REFS+=$(grep -oh '`make [a-z][a-z_-]*`' "$file" 2>/dev/null | sed 's/`//g; s/make //' || true)
        BACKTICK_REFS+=$'\n'
    fi
done

# Extract referenced targets from docs (code block lines starting with make)
CODE_BLOCK_REFS=""
for file in "${DOC_FILES[@]}"; do
    if [ -f "$file" ]; then
        CODE_BLOCK_REFS+=$(grep -h '^make [a-z][a-z_-]' "$file" 2>/dev/null | awk '{print $2}' || true)
        CODE_BLOCK_REFS+=$'\n'
    fi
done

# Merge and deduplicate all referenced targets
mapfile -t ALL_MAKE_REFS < <(printf '%s\n' "$BACKTICK_REFS" "$CODE_BLOCK_REFS" | grep -v '^$' | sort -u)

MAKE_PASS=0
MAKE_FAIL=0

for ref in "${ALL_MAKE_REFS[@]}"; do
    [ -z "$ref" ] && continue
    if printf '%s\n' "${ACTUAL_TARGETS[@]}" | grep -qx "$ref"; then
        echo "  PASS: make $ref"
        MAKE_PASS=$((MAKE_PASS + 1))
        PASSES=$((PASSES + 1))
    else
        echo "  FAIL: 'make $ref' referenced in docs but not in Makefile"
        MAKE_FAIL=$((MAKE_FAIL + 1))
        ERRORS=$((ERRORS + 1))
    fi
done

echo "Make targets: $MAKE_PASS passed, $MAKE_FAIL failed"
echo ""

# ═══════════════════════════════════════════
# === Config Vars ===
# ═══════════════════════════════════════════
echo "=== Config Vars ==="

# Extract known variable names from .env.example
mapfile -t KNOWN_VARS < <(grep -E '^[A-Z_]+=' "$ENV_EXAMPLE" | cut -d= -f1)

# Extract backtick-wrapped uppercase names WITH underscores from docs
# The underscore requirement filters out protocol names like TCP, HTTP, DNS
DOC_VARS_UNDERSCORE=""
for file in "${DOC_FILES[@]}"; do
    if [ -f "$file" ]; then
        DOC_VARS_UNDERSCORE+=$(grep -oh '`[A-Z][A-Z0-9_]*_[A-Z0-9_]*`' "$file" 2>/dev/null | sed 's/`//g' || true)
        DOC_VARS_UNDERSCORE+=$'\n'
    fi
done

# Also extract single-word backtick-wrapped uppercase names that match
# known .env.example vars (e.g., PORT)
DOC_VARS_SINGLE=""
for file in "${DOC_FILES[@]}"; do
    if [ -f "$file" ]; then
        # Extract backtick-wrapped single uppercase words (no underscore)
        candidates=$(grep -oh '`[A-Z][A-Z0-9]*`' "$file" 2>/dev/null | sed 's/`//g' || true)
        for candidate in $candidates; do
            # Only include if it exactly matches a known .env.example var
            if printf '%s\n' "${KNOWN_VARS[@]}" | grep -qx "$candidate"; then
                DOC_VARS_SINGLE+="$candidate"$'\n'
            fi
        done
    fi
done

# Merge and deduplicate
mapfile -t ALL_DOC_VARS < <(printf '%s\n' "$DOC_VARS_UNDERSCORE" "$DOC_VARS_SINGLE" | grep -v '^$' | sort -u)

VAR_PASS=0
VAR_FAIL=0

for var in "${ALL_DOC_VARS[@]}"; do
    [ -z "$var" ] && continue
    if printf '%s\n' "${KNOWN_VARS[@]}" | grep -qx "$var"; then
        echo "  PASS: $var"
        VAR_PASS=$((VAR_PASS + 1))
        PASSES=$((PASSES + 1))
    else
        echo "  FAIL: '$var' referenced in docs but not in .env.example"
        VAR_FAIL=$((VAR_FAIL + 1))
        ERRORS=$((ERRORS + 1))
    fi
done

echo "Config vars: $VAR_PASS passed, $VAR_FAIL failed"
echo ""

# ═══════════════════════════════════════════
# === File Paths ===
# ═══════════════════════════════════════════
echo "=== File Paths ==="

# Extract backtick-wrapped paths from docs that look like file/directory references
ALL_PATHS=""
for file in "${DOC_FILES[@]}"; do
    if [ -f "$file" ]; then
        ALL_PATHS+=$(grep -oh '`[^`]*[./][^`]*`' "$file" 2>/dev/null | sed 's/`//g' || true)
        ALL_PATHS+=$'\n'
    fi
done

mapfile -t PATH_REFS < <(printf '%s\n' "$ALL_PATHS" | grep -v '^$' | sort -u)

PATH_PASS=0
PATH_FAIL=0

for path_ref in "${PATH_REFS[@]}"; do
    [ -z "$path_ref" ] && continue

    # --- Skip filters ---

    # Skip paths starting with / (container paths like /app/output, /etc/)
    [[ "$path_ref" == /* ]] && continue

    # Skip URLs (contain ://)
    [[ "$path_ref" == *"://"* ]] && continue

    # Skip wildcards
    [[ "$path_ref" == *"*"* ]] && continue
    [[ "$path_ref" == *"?"* ]] && continue

    # Skip version strings (v1.0, v2.0, etc.)
    [[ "$path_ref" =~ ^v[0-9]+\.[0-9]+ ]] && continue

    # Skip strings containing spaces (commands, prose, error messages)
    [[ "$path_ref" == *" "* ]] && continue

    # Skip HTML tags (contain < or >)
    [[ "$path_ref" == *"<"* ]] && continue
    [[ "$path_ref" == *">"* ]] && continue

    # Skip anchor links (contain #)
    [[ "$path_ref" == *"#"* ]] && continue

    # Skip domain names (contain .com, .org, .io, .net)
    [[ "$path_ref" == *".com"* ]] && continue
    [[ "$path_ref" == *".org"* ]] && continue
    [[ "$path_ref" == *".io"* ]] && continue
    [[ "$path_ref" == *".net"* ]] && continue

    # Skip strings that are just .. or ../
    [[ "$path_ref" == ".." ]] && continue
    [[ "$path_ref" == "../" ]] && continue

    # Skip bare format references (just a dot-extension with no filename prefix)
    # e.g., ".yaml" or ".md" alone -- but allow "file.yaml" or ".env"
    [[ "$path_ref" =~ ^\.[a-z]+$ ]] && [[ "$path_ref" != .env* ]] && continue

    # Skip config var values that look like paths but are env example content
    # (e.g., FLASK_ENV=development lines from code blocks)
    [[ "$path_ref" == *"="* ]] && continue

    # Skip percent-encoded strings (URL components like %27, %3C)
    [[ "$path_ref" == *"%"* ]] && continue

    # Skip pipe characters (shell commands)
    [[ "$path_ref" == *"|"* ]] && continue

    # Skip strings starting with -- (command flags)
    [[ "$path_ref" == --* ]] && continue

    # Skip known non-repo path references:
    # - challenge.yml: ctfcli format name, not a file in this repo
    # - ctf-pcaps/: the clone directory name, not a path within the repo
    [[ "$path_ref" == "challenge.yml" ]] && continue
    [[ "$path_ref" == "ctf-pcap-generator/" ]] && continue

    # --- Existence check ---

    found=false

    # Check at repo root
    if [ -e "$path_ref" ]; then
        found=true
    fi

    # For .yaml files without a directory prefix, check scenarios/
    if [ "$found" = false ] && [[ "$path_ref" == *.yaml ]] && [[ "$path_ref" != */* ]]; then
        if [ -e "scenarios/$path_ref" ]; then
            found=true
        fi
    fi

    # For bare directory names (no / prefix, ending in /), check ctf_pcaps/
    if [ "$found" = false ] && [[ "$path_ref" == */ ]] && [[ "$path_ref" != */* || "$path_ref" =~ ^[a-z]+/$ ]]; then
        if [ -e "ctf_pcaps/$path_ref" ]; then
            found=true
        fi
    fi

    # For bare directory names without trailing /, also check ctf_pcaps/
    if [ "$found" = false ] && [[ "$path_ref" != */* ]] && [[ "$path_ref" != *.* ]]; then
        if [ -d "ctf_pcaps/$path_ref" ]; then
            found=true
        fi
    fi

    if [ "$found" = true ]; then
        echo "  PASS: $path_ref"
        PATH_PASS=$((PATH_PASS + 1))
        PASSES=$((PASSES + 1))
    else
        echo "  FAIL: '$path_ref' referenced in docs but not found"
        PATH_FAIL=$((PATH_FAIL + 1))
        ERRORS=$((ERRORS + 1))
    fi
done

echo "File paths: $PATH_PASS passed, $PATH_FAIL failed"

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo ""
echo "Total: $PASSES passed, $ERRORS failed"

if [ "$ERRORS" -gt 0 ]; then
    exit 1
fi

exit 0
