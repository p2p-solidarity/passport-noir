#!/usr/bin/env bash
# Auto-version release script
# Usage: ./scripts/release.sh [patch|minor|major]
# Creates a version tag and pushes it to trigger the release workflow.
set -euo pipefail

BUMP="${1:-patch}"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Get latest version tag
LATEST=$(git tag -l 'v*' --sort=-v:refname | head -1 2>/dev/null || echo "v0.0.0")
echo "  Current version: $LATEST"

# Parse semver
VERSION="${LATEST#v}"
IFS='.' read -r MAJOR MINOR PATCH <<< "$VERSION"

case "$BUMP" in
  patch) PATCH=$((PATCH + 1)) ;;
  minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
  major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
  *)
    echo -e "${RED}Usage: $0 [patch|minor|major]${NC}"
    exit 1
    ;;
esac

NEW_VERSION="v${MAJOR}.${MINOR}.${PATCH}"
echo -e "  New version: ${GREEN}${NEW_VERSION}${NC} (${BUMP} bump)"

# Verify clean working tree
if [ -n "$(git status --porcelain)" ]; then
  echo -e "${YELLOW}Warning: working tree is not clean.${NC}"
  echo "  Commit or stash changes before releasing."
  exit 1
fi

# Verify on main branch
BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ]; then
  echo -e "${YELLOW}Warning: not on main branch (currently on $BRANCH).${NC}"
  read -r -p "  Continue anyway? [y/N] " REPLY
  [[ "$REPLY" =~ ^[Yy]$ ]] || exit 1
fi

# Update Package.swift URL with new version
PACKAGE_FILE="Package.swift"
if [ -f "$PACKAGE_FILE" ]; then
  # Update the download URL version
  sed -i '' "s|releases/download/v[0-9]*\.[0-9]*\.[0-9]*/|releases/download/${NEW_VERSION}/|g" "$PACKAGE_FILE"
  if git diff --quiet "$PACKAGE_FILE"; then
    echo "  Package.swift already up to date."
  else
    echo "  Updated Package.swift download URL to ${NEW_VERSION}"
    git add "$PACKAGE_FILE"
    git commit -m "chore: bump Package.swift to ${NEW_VERSION}"
  fi
fi

# Create annotated tag
echo "  Creating tag ${NEW_VERSION}..."
git tag -a "$NEW_VERSION" -m "Release ${NEW_VERSION}"

echo ""
echo -e "${GREEN}Tag ${NEW_VERSION} created.${NC}"
echo ""
echo "  Push to trigger release workflow:"
echo "    git push origin main --tags"
echo ""
echo "  Or push tag only:"
echo "    git push origin ${NEW_VERSION}"
