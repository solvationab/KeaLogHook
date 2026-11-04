#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
: "${GITHUB_REF_NAME:?GITHUB_REF_NAME must be set}"
: "${CLOUDSMITH_WORKSPACE:?CLOUDSMITH_WORKSPACE must be set}"
: "${CLOUDSMITH_REPOSITORY:?CLOUDSMITH_REPOSITORY must be set}"
if [[ ! "$GITHUB_REF_NAME" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo 'Release tags must use vMAJOR.MINOR.PATCH' >&2
    exit 1
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
package_dir=${1:-packages}
version=${GITHUB_REF_NAME#v}
output_dir="$package_dir/release-docs/$GITHUB_REF_NAME"
mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd)
assets=()
shopt -s nullglob
for distribution in noble resolute el9; do
    packages=("$package_dir/$distribution"/*.deb "$package_dir/$distribution"/*.rpm)
    if ((${#packages[@]} == 0)); then
        echo "No packages found for $distribution" >&2
        exit 1
    fi
    for package in "${packages[@]}"; do
        filename=$(basename "$package")
        target="$output_dir/${filename%.*}_${distribution}.${filename##*.}"
        cp "$package" "$target"
        assets+=("$target")
    done
done

project_url="${GITHUB_SERVER_URL:-https://github.com}/$GITHUB_REPOSITORY"
source_url="$project_url/blob/$GITHUB_REF_NAME"
cloudsmith_url="https://cloudsmith.io/~$CLOUDSMITH_WORKSPACE/repos/$CLOUDSMITH_REPOSITORY"
notes="$output_dir/release-notes.md"
printf '%s\n' \
    "# Kea IP Audit Hook $version" '' \
    "[Quick start]($source_url/README.md#quick-start) | [Operations]($source_url/docs/operations.md) | [Configuration]($source_url/docs/configuration.md) | [Fields]($source_url/docs/fields.md)" '' \
    "[GitHub source]($project_url/tree/$GITHUB_REF_NAME) | [Cloudsmith packages]($cloudsmith_url/packages/) | [Cloudsmith Set Me Up]($cloudsmith_url/setup/)" '' \
    '## Install' '' \
    'Choose the asset for Ubuntu 24.04 (noble), Ubuntu 26.04 (resolute), or EL9. Match the server architecture and Kea version; rebuild after upgrading Kea.' '' \
    'After configuring the Cloudsmith repository using Set Me Up:' '' \
    '```sh' \
    'sudo apt update && sudo apt install kea-ip-audit-hook  # Ubuntu' \
    'sudo dnf install kea-ip-audit-hook                    # EL9' \
    '```' '' \
    'Alternatively, download one matching package asset and install with apt install ./<file>.deb or dnf install ./<file>.rpm. Verify downloads against SHA256SUMS; these are integrity checks, not signatures.' '' \
    'Packages do not enable the hook or restart DHCP. Follow the quick start to locate the library, configure Kea, check log access, and verify IP_AUDIT_LOAD_OK.' '' \
    'Both ip-audit-lookup and ip-audit-list are included. The docs archive contains the README, operations/configuration/field references, and examples for this version.' \
    > "$notes"
archive="$output_dir/kea-ip-audit-docs-$version.tar.gz"
tar -czf "$archive" -C "$repo_root" README.md docs examples man
assets+=("$archive")
(
    cd "$output_dir"
    for asset in "${assets[@]}"; do
        sha256sum "$(basename "$asset")"
    done > SHA256SUMS
)
assets+=("$output_dir/SHA256SUMS")

cloudsmith push raw "$CLOUDSMITH_WORKSPACE/$CLOUDSMITH_REPOSITORY" "$archive" \
    --name kea-ip-audit-docs --version "$version" --republish \
    --summary 'Kea IP Audit Hook installation, configuration, and examples' \
    --description "$(cat "$notes")" --tags "documentation,$GITHUB_REF_NAME"

if gh release view "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
    gh release edit "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY" --notes-file "$notes"
    gh release upload "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY" --clobber "${assets[@]}"
else
    gh release create "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY" --verify-tag \
        --title "Kea IP Audit Hook $version" --notes-file "$notes" "${assets[@]}"
fi
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    cat "$notes" >> "$GITHUB_STEP_SUMMARY"
fi