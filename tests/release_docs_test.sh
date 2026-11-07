#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/packages/noble" "$work/packages/resolute" "$work/packages/el9"
for distribution in noble resolute; do
    printf 'test DEB\n' > "$work/packages/$distribution/kea-ip-audit-hook_1.2.3_amd64.deb"
done
printf 'test RPM\n' > "$work/packages/el9/kea-ip-audit-hook-1.2.3-1.x86_64.rpm"
printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\n" "$@" >> "$MOCK_CLOUDSMITH_LOG"' \
    'exit "${MOCK_CLOUDSMITH_STATUS:-0}"' > "$work/bin/cloudsmith"
printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\n" "$@" >> "$MOCK_GH_LOG"' \
    'if [[ "$1 $2" = "release view" ]]; then exit "${MOCK_GH_VIEW_STATUS:-1}"; fi' \
    > "$work/bin/gh"
chmod +x "$work/bin/cloudsmith" "$work/bin/gh"
export PATH="$work/bin:$PATH"
export GITHUB_REPOSITORY=example/kea GITHUB_REF_NAME=v1.2.3
export CLOUDSMITH_WORKSPACE=example CLOUDSMITH_REPOSITORY=kea
export MOCK_CLOUDSMITH_LOG="$work/cloudsmith" MOCK_GH_LOG="$work/gh"
export GITHUB_STEP_SUMMARY="$work/summary"
bash "$repo_root/scripts/publish-release-docs.sh" "$work/packages"
output="$work/packages/release-docs/v1.2.3"
test -f "$output/kea-ip-audit-hook_1.2.3_amd64_noble.deb"
test -f "$output/kea-ip-audit-hook_1.2.3_amd64_resolute.deb"
tar -tzf "$output/kea-ip-audit-docs-1.2.3.tar.gz" | grep -Fx docs/operations.md
for file in docs/developer/integration.md docs/developer/wire-format.md \
    docs/developer/compatibility.md docs/developer/recovery.md docs/audit-record.schema.json \
    examples/developer/listener.py examples/developer/publisher.py \
    examples/developer/records.jsonl examples/developer/requirements.txt; do
    tar -tzf "$output/kea-ip-audit-docs-1.2.3.tar.gz" | grep -Fx "$file"
done
tar -tzf "$output/kea-ip-audit-docs-1.2.3.tar.gz" | grep -Fx man/man1/ip-audit-lookup.1
tar -tzf "$output/kea-ip-audit-docs-1.2.3.tar.gz" | grep -Fx man/man1/ip-audit-list.1
tar -tzf "$output/kea-ip-audit-docs-1.2.3.tar.gz" | grep -Fx man/man1/ip-audit-subscriber.1
tar -tzf "$output/kea-ip-audit-docs-1.2.3.tar.gz" | grep -Fx man/man1/ip-audit-check.1
tar -tzf "$output/kea-ip-audit-docs-1.2.3.tar.gz" | grep -Fx man/man1/ip-audit-report.1
grep -Fq 'https://github.com/example/kea/blob/v1.2.3/README.md#quick-start' "$output/release-notes.md"
grep -Fq 'https://cloudsmith.io/~example/repos/kea/setup/' "$output/release-notes.md"
grep -Fxq -- '--verify-tag' "$work/gh"
grep -Fxq -- '--description' "$work/cloudsmith"
grep -Fq 'ip-audit-list' "$work/summary"
grep -Fq 'ip-audit-subscriber' "$output/release-notes.md"
grep -Fq 'ip-audit-check' "$output/release-notes.md"
grep -Fq 'ip-audit-report' "$output/release-notes.md"
(cd "$output" && sha256sum -c SHA256SUMS)
MOCK_GH_VIEW_STATUS=0 bash "$repo_root/scripts/publish-release-docs.sh" "$work/packages"
grep -Fxq upload "$work/gh"
rm "$work/gh"
if MOCK_CLOUDSMITH_STATUS=1 bash "$repo_root/scripts/publish-release-docs.sh" "$work/packages"; then
    echo 'Expected upload failure to stop publishing' >&2
    exit 1
fi
test ! -e "$work/gh"
if GITHUB_REF_NAME=main bash "$repo_root/scripts/publish-release-docs.sh" "$work/packages"; then
    echo 'Expected invalid release tag to fail' >&2
    exit 1
fi
printf 'Release documentation tests passed\n'