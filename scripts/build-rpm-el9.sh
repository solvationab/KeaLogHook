#!/usr/bin/env bash
set -euo pipefail

: "${KEA_IP_AUDIT_VERSION:?KEA_IP_AUDIT_VERSION must be set}"
RPM_ARTIFACT_DIR="${RPM_ARTIFACT_DIR:-/src/rpm-artifacts}"

dnf -y install dnf-plugins-core
dnf config-manager --set-enabled crb
dnf -y install epel-release
dnf -y install cmake gcc-c++ make pkgconf-pkg-config boost-devel \
    openssl-devel zlib-devel zeromq-devel kea kea-devel rpm-build

build_dir="/tmp/kea-ip-audit-build"
cmake -S /src -B "$build_dir" -DCMAKE_BUILD_TYPE=Release -DKEA_PREFIX=/usr \
    -DCMAKE_INSTALL_LIBDIR=lib64 -DKEA_IP_AUDIT_VERSION="$KEA_IP_AUDIT_VERSION" \
    -DIP_AUDIT_BUILD_TESTS=OFF
cmake --build "$build_dir" --parallel
cpack --config "$build_dir/CPackConfig.cmake" -G RPM -B "$build_dir/packages"

dnf -y install "$build_dir"/packages/*.rpm
if ldd /usr/lib64/kea/hooks/libdhcp_ip_audit.so | grep -q "not found"; then
    echo "EL9 hook package has unresolved shared libraries" >&2
    exit 1
fi

mkdir -p "$RPM_ARTIFACT_DIR"
cp "$build_dir"/packages/*.rpm "$RPM_ARTIFACT_DIR"/