#!/usr/bin/env bash
# Releases a new kring version: bumps the workspace version in Cargo.toml and
# Cargo.lock, runs the same checks as the GitHub Actions release workflow
# (.github/workflows/release.yml), commits, tags v<version> and pushes branch
# and tag. The pushed tag starts the release workflow.
#
# Nothing is committed, tagged or pushed unless every check passes; if one
# fails, the version bump is reverted.
#
# Usage: scripts/release.sh [--force] [--skip-checks] <version>
#   <version>      new version as MAJOR.MINOR.PATCH, e.g. 0.1.2
#   --force        skip the "on master", "clean working tree" and
#                  "up to date with remote" checks
#   --skip-checks  skip the local fmt, clippy and test run (not recommended)
set -euo pipefail

cd "$(dirname "$0")/.."

# Branch releases are made from.
RELEASE_BRANCH="master"
# Remote the branch and the tag are pushed to.
REMOTE="origin"
# Accepted version format.
VERSION_RE='^[0-9]+\.[0-9]+\.[0-9]+$'
# Tools the checks and the release need (the CI test job also installs gpg
# and ssh, which the tests call).
REQUIRED_TOOLS=(git cargo python3 gpg ssh)

# Prints an error and exits.
die() {
    echo "release: $*" >&2
    exit 1
}

# Prints the usage and exits with the given code.
usage() {
    echo "Usage: $0 [--force] [--skip-checks] <version>   (version as MAJOR.MINOR.PATCH, e.g. 0.1.2)" >&2
    exit "${1:-1}"
}

# Prints the current workspace version from Cargo.toml.
current_version() {
    sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1
}

# Prints the version of the kring package as cargo sees it.
cargo_package_version() {
    cargo metadata --no-deps --format-version 1 --offline \
        | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "kring"))'
}

# Runs the checks of the release workflow "check" job. Exits on the first failure.
run_checks() {
    echo "release: GUI toolkit guard"
    bash scripts/check-no-gui-toolkits.sh || die "GUI toolkit guard failed"
    echo "release: cargo fmt"
    cargo fmt --all -- --check || die "cargo fmt failed (run cargo fmt --all)"
    echo "release: cargo clippy"
    cargo clippy --workspace --all-targets -- -D warnings || die "cargo clippy failed"
    echo "release: cargo test"
    cargo test --workspace || die "cargo test failed"
}

# Restores the files changed by the version bump. Used as an EXIT trap while
# the bump is not committed yet.
revert_bump() {
    echo "release: failed, reverting the version bump" >&2
    git checkout --quiet -- Cargo.toml Cargo.lock
}

force=0
skip_checks=0
version=""
for arg in "$@"; do
    case "$arg" in
        --force) force=1 ;;
        --skip-checks) skip_checks=1 ;;
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

for tool in "${REQUIRED_TOOLS[@]}"; do
    command -v "$tool" >/dev/null || die "required tool not found: $tool"
done

git rev-parse --quiet --verify "refs/tags/$tag" >/dev/null && die "tag $tag already exists locally"
git ls-remote --exit-code --tags "$REMOTE" "refs/tags/$tag" >/dev/null 2>&1 && die "tag $tag already exists on $REMOTE"

# The remote must be reachable and the branch must not be behind it, or the
# push would be rejected after the commit and the tag are already created.
if [ -n "$branch" ] && [ "$force" -eq 0 ]; then
    git fetch --quiet "$REMOTE" "$branch" || die "cannot fetch $REMOTE/$branch"
    behind="$(git rev-list --count "HEAD..FETCH_HEAD")"
    [ "$behind" -eq 0 ] || die "$branch is $behind commit(s) behind $REMOTE/$branch; pull first or use --force"
fi

old="$(current_version)"
[ -n "$old" ] || die "cannot read the workspace version from Cargo.toml"

if [ "$old" != "$version" ] && [ -n "$(git status --porcelain -- Cargo.toml Cargo.lock)" ]; then
    die "Cargo.toml or Cargo.lock has uncommitted changes; they would end up in the release commit"
fi

# Bump the version (not committed yet) and make sure it is what the release
# workflow will read: it fails when the tag differs from the package version.
trap revert_bump EXIT
if [ "$old" != "$version" ]; then
    echo "release: bumping version $old -> $version"
    sed -i "0,/^version = \"$old\"$/s//version = \"$version\"/" Cargo.toml
    [ "$(current_version)" = "$version" ] || die "version bump in Cargo.toml failed"
    cargo update --workspace --offline --quiet || die "cargo update failed, Cargo.lock not refreshed"
else
    echo "release: Cargo.toml already at $version, no bump needed"
fi
[ "$(cargo_package_version)" = "$version" ] || die "package kring is not at version $version after the bump"

if [ "$skip_checks" -eq 1 ]; then
    echo "release: WARNING checks skipped"
else
    run_checks
fi

# Everything passed: from here the bump is kept.
trap - EXIT
if [ "$old" != "$version" ]; then
    git add Cargo.toml Cargo.lock
    git commit --quiet -m "chore: release $tag"
fi

git tag -a "$tag" -m "kring $version"

# If the push fails, drop the local tag so the script can be run again.
if [ -n "$branch" ]; then
    git push --atomic "$REMOTE" "$branch" "$tag" || { git tag -d "$tag" >/dev/null; die "push failed, local tag $tag removed"; }
else
    git push "$REMOTE" "$tag" || { git tag -d "$tag" >/dev/null; die "push failed, local tag $tag removed"; }
fi
echo "release: pushed $tag; the release workflow is starting on GitHub"
