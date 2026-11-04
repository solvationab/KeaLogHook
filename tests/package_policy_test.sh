#!/bin/sh
set -eu
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
parser=$(command -v apparmor_parser || true)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
export IP_AUDIT_POLICY_ROOT="$work"
mkdir -p "$work/etc/apparmor.d/local" "$work/sys/module/apparmor/parameters" "$work/bin"
printf 'Y\n' > "$work/sys/module/apparmor/parameters/enabled"
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "$IP_AUDIT_POLICY_ROOT/reloads"\n' > "$work/bin/apparmor_parser"
chmod +x "$work/bin/apparmor_parser"
export PATH="$work/bin:$PATH"
for name in kea-dhcp4 usr.sbin.kea-dhcp6; do
    printf '#include if exists <local/%s>\n' "$name" > "$work/etc/apparmor.d/$name"
    printf '/administrator/rule r,\n' > "$work/etc/apparmor.d/local/$name"
done
sh "$source_dir/packaging/security-policy" configure
sh "$source_dir/packaging/security-policy" configure
for name in kea-dhcp4 usr.sbin.kea-dhcp6; do
    local="$work/etc/apparmor.d/local/$name"
    [ "$(grep -Fc '#include if exists <abstractions/kea-ip-audit>' "$local")" = 1 ]
    grep -Fxq '/administrator/rule r,' "$local"
done
[ "$(wc -l < "$work/reloads" | tr -d ' ')" = 4 ]
sh "$source_dir/packaging/security-policy" remove
sh "$source_dir/packaging/security-policy" remove
[ "$(wc -l < "$work/reloads" | tr -d ' ')" = 6 ]
for name in kea-dhcp4 usr.sbin.kea-dhcp6; do
    local="$work/etc/apparmor.d/local/$name"
    ! grep -Fq 'abstractions/kea-ip-audit' "$local"
    grep -Fxq '/administrator/rule r,' "$local"
done
mkdir -p "$work/libexec/kea-ip-audit"
cp "$source_dir/packaging/security-policy" "$work/libexec/kea-ip-audit/security-policy"
chmod +x "$work/libexec/kea-ip-audit/security-policy"
for script in postinst prerm; do
    sed "s|@CMAKE_INSTALL_FULL_LIBEXECDIR@|$work/libexec|g" \
        "$source_dir/packaging/$script.in" > "$work/$script"
done
sh "$work/postinst" configure
sh "$work/prerm" upgrade
sh "$work/postinst" 2
sh "$work/prerm" 1
grep -Fq 'abstractions/kea-ip-audit' "$work/etc/apparmor.d/local/kea-dhcp4"
sh "$work/prerm" remove
! grep -Fq 'abstractions/kea-ip-audit' "$work/etc/apparmor.d/local/kea-dhcp4"
sh "$work/postinst" 1
sh "$work/prerm" 0
! grep -Fq 'abstractions/kea-ip-audit' "$work/etc/apparmor.d/local/kea-dhcp4"
rm "$work/sys/module/apparmor/parameters/enabled" "$work/reloads"
rm "$work/etc/apparmor.d/local/kea-dhcp4"
sh "$source_dir/packaging/security-policy" configure
test ! -e "$work/reloads"
grep -Fxq '#include if exists <abstractions/kea-ip-audit>' "$work/etc/apparmor.d/local/kea-dhcp4"
printf '# unsupported profile\n' > "$work/etc/apparmor.d/kea-dhcp6"
sh "$source_dir/packaging/security-policy" configure 2> "$work/warnings"
grep -Fq 'configure AppArmor manually' "$work/warnings"
test ! -e "$work/etc/apparmor.d/local/kea-dhcp6"
if [ -n "$parser" ]; then
    mkdir -p "$work/etc/apparmor.d/abstractions"
    cp "$source_dir/packaging/kea-ip-audit.apparmor" "$work/etc/apparmor.d/abstractions/kea-ip-audit"
    printf 'profile kea-ip-audit-test {\n#include <local/kea-dhcp4>\n}\n' > "$work/profile"
    "$parser" -Q -T -I "$work/etc/apparmor.d" "$work/profile"
fi
rm "$work/etc/apparmor.d/kea-dhcp4"
sh "$source_dir/packaging/security-policy" remove
! grep -Fq 'abstractions/kea-ip-audit' "$work/etc/apparmor.d/local/kea-dhcp4"
rm -rf "$work/etc/apparmor.d"
sh "$source_dir/packaging/security-policy" configure
sh "$source_dir/packaging/security-policy" remove
printf 'Package policy lifecycle tests passed\n'