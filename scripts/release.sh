#!/usr/bin/env bash
# Releases a new kring version: bumps the workspace version, commits it,
# tags v<version> and pushes branch and tag. The pushed tag starts the
# GitHub Actions release workflow (.github/workflows/ci.yml).
#
# Usage: scripts/release.sh [--force] <version>
#   <version>  new version as MAJOR.MINOR.PATCH, e.g. 0.1.2
#   --force    skip the "on master" and "clean working tree" checks
set -euo pipefail

cd "$(dirname "$0")/.."

# Branch releases are made from.
RELEASE_BRANCH="master"
# Remote the branch and the tag are pushed to.
REMOTE="origin"
# Accepted version format.
VERSION_RE='^[0-9]+\.[0-9]+\.[0-9]+$'

# Prints an error and exits.
die() {
    echo "release: $*" >&2
    exit 1
}

# Prints the usage and exits with the given code.
usage() {
    echo "Usage: $0 [--force] <version>   (version as MAJOR.MINOR.PATCH, e.g. 0.1.2)" >&2
    exit "${1:-1}"
}

# Prints the current workspace version from Cargo.toml.
current_version() {
    sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1
}

force=0
version=""
for arg in "$@"; do
    case "$arg" in
        --force) force=1 ;;
        -h|--help) usage 0 ;;
        -*) die "unknown option: $arg" ;;
        *)
            [ -z "$version" ] || die "only one version can be given"
            version="$arg"
            ;;
    esac
done

[ -n "$version" ] || usage
[[ "$version" =~ $VERSION_RE ]] || die "invalid version '$version' (expected MAJOR.MINOR.PATCH, e.g. 0.1.2)"
tag="v$version"

branch="$(git symbolic-ref --quiet --short HEAD || true)"
if [ "$force" -eq 0 ]; then
    [ "$branch" = "$RELEASE_BRANCH" ] || die "not on $RELEASE_BRANCH (on '${branch:-detached HEAD}'); use --force to release anyway"
    [ -z "$(git status --porcelain)" ] || die "working tree has uncommitted or untracked files; commit them or use --force"
fi

git rev-parse --quiet --verify "refs/tags/$tag" >/dev/null && die "tag $tag already exists locally"
git ls-remote --exit-code --tags "$REMOTE" "refs/tags/$tag" >/dev/null 2>&1 && die "tag $tag already exists on $REMOTE"

old="$(current_version)"
[ -n "$old" ] || die "cannot read the workspace version from Cargo.toml"

if [ "$old" != "$version" ] && [ -n "$(git status --porcelain -- Cargo.toml Cargo.lock)" ]; then
    die "Cargo.toml or Cargo.lock has uncommitted changes; they would end up in the release commit"
fi

if [ "$old" != "$version" ]; then
    echo "release: bumping version $old -> $version"
    sed -i "0,/^version = \"$old\"$/s//version = \"$version\"/" Cargo.toml
    [ "$(current_version)" = "$version" ] || die "version bump in Cargo.toml failed"
    cargo update --workspace --offline --quiet
    git add Cargo.toml Cargo.lock
    git commit --quiet -m "chore: release $tag"
else
    echo "release: Cargo.toml already at $version, no bump commit"
fi

git tag -a "$tag" -m "kring $version"

if [ -n "$branch" ]; then
    git push --atomic "$REMOTE" "$branch" "$tag"
else
    git push "$REMOTE" "$tag"
fi
echo "release: pushed $tag; the release workflow is starting on GitHub"
