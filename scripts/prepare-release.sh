#!/usr/bin/env bash
# prepare-release.sh -- Build a fresh git repo with clean milestone history.
# IMPORTANT: This file must have LF line endings (not CRLF).
set -euo pipefail

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$(cd "$REPO_ROOT/.." && pwd)/ctf-pcap-generator-release"

# Milestone commit hashes (from dev repo history)
V1_0_COMMIT="28cf7b4"
V1_1_COMMIT="06c5239"

# Files/directories to exclude from ALL release commits
EXCLUDES=(
    ".planning/"
    ".claude/"
    ".env"
    "nul"
    "CLAUDE.md"
)

# ─────────────────────────────────────────────
# Helper: extract_milestone
# Extracts files from a specific commit into the build directory,
# skipping excluded paths and output/*.pcap files.
# Usage: extract_milestone <commit> <build_dir>
# ─────────────────────────────────────────────
extract_milestone() {
    local commit="$1"
    local build_dir="$2"

    cd "$REPO_ROOT"

    git ls-tree -r --name-only "$commit" | while IFS= read -r filepath; do
        # Check against exclusion list
        local skip=false
        for excl in "${EXCLUDES[@]}"; do
            case "$excl" in
                */)
                    # Directory exclusion: match prefix
                    case "$filepath" in
                        "${excl}"*) skip=true; break ;;
                    esac
                    ;;
                *)
                    # File exclusion: exact match
                    if [ "$filepath" = "$excl" ]; then
                        skip=true
                        break
                    fi
                    ;;
            esac
        done
        [ "$skip" = true ] && continue

        # Special handling for output/ directory: keep only .gitkeep
        case "$filepath" in
            output/*)
                if [ "$filepath" != "output/.gitkeep" ]; then
                    continue
                fi
                ;;
        esac

        # Extract file content and write to build directory
        mkdir -p "$build_dir/$(dirname "$filepath")"
        git show "$commit:$filepath" > "$build_dir/$filepath"
    done
}

# ─────────────────────────────────────────────
# Helper: replace_placeholders
# Performs all placeholder replacements in the build directory.
# Usage: replace_placeholders <directory>
# ─────────────────────────────────────────────
replace_placeholders() {
    local dir="$1"

    # Primary: profzeller/ctf-pcap-generator -> profzeller/ctf-pcap-generator
    find "$dir" -type f \( -name "*.md" -o -name "*.yml" -o -name "*.yaml" -o -name "*.toml" -o -name "*.sh" \) \
        -exec sed -i 's|profzeller/ctf-pcap-generator|profzeller/ctf-pcap-generator|g' {} +

    # Clone directory name: cd ctf-pcaps -> cd ctf-pcap-generator
    find "$dir" -type f -name "*.md" \
        -exec sed -i 's|cd ctf-pcaps|cd ctf-pcap-generator|g' {} +

    # Directory reference in prose: `ctf-pcaps/` -> `ctf-pcap-generator/`
    find "$dir" -type f -name "*.md" \
        -exec sed -i 's|`ctf-pcaps/`|`ctf-pcap-generator/`|g' {} +

    # Docker image name in example output: ctf-pcaps-web -> ctf-pcap-generator-web
    find "$dir" -type f -name "*.md" \
        -exec sed -i 's|ctf-pcaps-web|ctf-pcap-generator-web|g' {} +

    # verify-docs.sh skip list: "ctf-pcap-generator/" -> "ctf-pcap-generator/"
    find "$dir" -type f -name "*.sh" \
        -exec sed -i 's|"ctf-pcap-generator/"|"ctf-pcap-generator/"|g' {} +

    # Remove lychee YOUR-USERNAME exclusion (links are now real)
    if [ -f "$dir/.lychee.toml" ]; then
        sed -i '/YOUR-USERNAME/d' "$dir/.lychee.toml"
    fi

    # pyproject.toml: update package name metadata (import path stays ctf_pcaps)
    if [ -f "$dir/pyproject.toml" ]; then
        sed -i 's|name = "ctf-pcaps"|name = "ctf-pcap-generator"|g' "$dir/pyproject.toml"
    fi
}

# ─────────────────────────────────────────────
# Helper: verify_no_leaks
# Checks the build directory for development artifacts or
# unreplaced placeholder strings. Exits non-zero if any found.
# Usage: verify_no_leaks
# ─────────────────────────────────────────────
verify_no_leaks() {
    local leaks=0

    echo "Checking for placeholder leaks..."
    local username_hits
    username_hits=$(grep -r --include="*.md" --include="*.yml" --include="*.yaml" \
        --include="*.toml" --include="*.sh" --include="*.py" \
        "YOUR-USERNAME" "$BUILD_DIR" 2>/dev/null | wc -l)
    if [ "$username_hits" -gt 0 ]; then
        echo "  FAIL: Found $username_hits YOUR-USERNAME references:"
        grep -r --include="*.md" --include="*.yml" --include="*.yaml" \
            --include="*.toml" --include="*.sh" --include="*.py" \
            "YOUR-USERNAME" "$BUILD_DIR" 2>/dev/null || true
        leaks=$((leaks + 1))
    else
        echo "  PASS: No YOUR-USERNAME placeholders"
    fi

    echo "Checking for Co-Authored-By in commit messages..."
    local coauth_hits
    coauth_hits=$(cd "$BUILD_DIR" && git log --format="%b" | grep -c "Co-Authored-By" 2>/dev/null || true)
    if [ "$coauth_hits" -gt 0 ]; then
        echo "  FAIL: Found $coauth_hits Co-Authored-By lines in commits"
        leaks=$((leaks + 1))
    else
        echo "  PASS: No Co-Authored-By lines"
    fi

    echo "Checking for dev artifact files..."
    if [ -d "$BUILD_DIR/.planning" ]; then
        echo "  FAIL: .planning/ directory exists"
        leaks=$((leaks + 1))
    else
        echo "  PASS: No .planning/ directory"
    fi

    if [ -d "$BUILD_DIR/.claude" ]; then
        echo "  FAIL: .claude/ directory exists"
        leaks=$((leaks + 1))
    else
        echo "  PASS: No .claude/ directory"
    fi

    if [ -f "$BUILD_DIR/CLAUDE.md" ]; then
        echo "  FAIL: CLAUDE.md exists"
        leaks=$((leaks + 1))
    else
        echo "  PASS: No CLAUDE.md"
    fi

    if [ -f "$BUILD_DIR/.env" ]; then
        echo "  FAIL: .env exists"
        leaks=$((leaks + 1))
    else
        echo "  PASS: No .env file"
    fi

    if [ -f "$BUILD_DIR/nul" ]; then
        echo "  FAIL: nul file exists"
        leaks=$((leaks + 1))
    else
        echo "  PASS: No nul file"
    fi

    if [ "$leaks" -gt 0 ]; then
        echo ""
        echo "VERIFICATION FAILED: $leaks leak(s) found"
        exit 1
    fi

    echo "  All checks passed"
}

# ─────────────────────────────────────────────
# Main Flow
# ─────────────────────────────────────────────
echo "=== CTF PCAP Generator Release Builder ==="
echo ""
echo "Source repo: $REPO_ROOT"
echo "Build dir:   $BUILD_DIR"
echo ""

# Step 1: Clean and init build directory
echo "Step 1: Initializing build directory..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
git init -b main
git config user.name "Jason Zeller"
git config user.email "profzeller@users.noreply.github.com"
echo ""

# Step 2: v1.0 milestone
echo "Step 2: Building v1.0 milestone ($V1_0_COMMIT)..."
extract_milestone "$V1_0_COMMIT" "$BUILD_DIR"
replace_placeholders "$BUILD_DIR"
cd "$BUILD_DIR"
git add -A
git commit -m "v1.0: Core PCAP generation engine"
git tag v1.0.0
echo "  v1.0 committed and tagged v1.0.0"
echo ""

# Step 3: v1.1 milestone
echo "Step 3: Building v1.1 milestone ($V1_1_COMMIT)..."
git rm -rf . --quiet 2>/dev/null || true
extract_milestone "$V1_1_COMMIT" "$BUILD_DIR"
replace_placeholders "$BUILD_DIR"
cd "$BUILD_DIR"
git add -A
git commit -m "v1.1: Scenarios and features expansion"
git tag v1.1.0
echo "  v1.1 committed and tagged v1.1.0"
echo ""

# Step 4: v2.0 milestone (current HEAD)
echo "Step 4: Building v2.0 milestone (HEAD)..."
git rm -rf . --quiet 2>/dev/null || true
extract_milestone "HEAD" "$BUILD_DIR"
replace_placeholders "$BUILD_DIR"
cd "$BUILD_DIR"
git add -A
git commit -m "v2.0: Documentation and public release"
echo "  v2.0 committed"
echo ""

# Step 5: Verify
echo "=== Verification ==="
verify_no_leaks
echo ""

# Step 6: Summary
echo "=== Release repo built successfully ==="
echo "Location: $BUILD_DIR"
echo ""
echo "Commits:"
git log --oneline --decorate
echo ""
echo "Next steps:"
echo "  1. Review the repo: cd $BUILD_DIR && git log --stat"
echo "  2. Create repo on GitHub: profzeller/ctf-pcap-generator"
echo "  3. Push: git remote add origin https://github.com/profzeller/ctf-pcap-generator.git && git push -u origin main --tags"
echo "  4. Push wiki separately (see wiki/ directory in source repo)"
