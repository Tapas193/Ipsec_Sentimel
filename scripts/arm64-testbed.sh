#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# IPsec Sentinel — ARM64 Linux testbed VM (lima)
#
# macOS cannot run StrongSwan/IPSec natively. In later phases the testbed (VPN
# gateway peers, strongswan charon, ipsec.conf) runs inside a Linux/arm64 VM.
# `lima` (https://lima-vm.io) provides lightweight QEMU/VZ VMs that use the M2's
# arm64 without x86 emulation.
#
# NOTE: This script ONLY provisions the VM environment. It does NOT install or
# configure StrongSwan — that belongs to a later phase.
#
# Usage:
#   ./scripts/arm64-testbed.sh up       # create + start the VM, mount the repo
#   ./scripts/arm64-testbed.sh shell    # interactive shell inside the VM
#   ./scripts/arm64-testbed.sh status
#   ./scripts/arm64-testbed.sh stop
#   ./scripts/arm64-testbed.sh delete
#
# Prereqs: brew install lima
# -----------------------------------------------------------------------------
set -euo pipefail

VM_NAME="ipsec-sentinel-testbed"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UBUNTU_IMAGE="https://cloud-images.ubuntu.com/24.04/current/24.04-cloud.img" # arm64

command -v lima >/dev/null 2>&1 || {
  echo "lima is not installed. Install it with:  brew install lima"
  echo "Then re-run this script."
  exit 1
}

case "$(uname -m)" in
  arm64|aarch64) ;;
  *)
    echo "This helper targets Apple Silicon (arm64). Detected: $(uname -m)"
    exit 1
    ;;
esac

# Minimal spec tuned for an M2: 2 vCPU, 4 GiB RAM. Bumped via overrides below.
VM_YAML="${TMPDIR:-/tmp}/${VM_NAME}.yaml"
cat > "${VM_YAML}" <<YAML
arch: "aarch64"
cpus: ${TESTBED_CPUS:-2}
memory: "${TESTBED_MEMORY:-4GiB}"
disk: "${TESTBED_DISK:-20GiB}"
images:
  - location: "${UBUNTU_IMAGE}"
    arch: "aarch64"
mounts:
  - location: "${PROJECT_ROOT}"
    writable: true
hostResolver:
  enabled: true
networks:
  - lima: shared
YAML

up() {
  echo "==> Creating ARM64 Linux VM '${VM_NAME}' (Ubuntu 24.04)…"
  echo "    CPU=${TESTBED_CPUS:-2} MEM=${TESTBED_MEMORY:-4GiB} DISK=${TESTBED_DISK:-20GiB}"
  lima --name "${VM_NAME}" start "${VM_YAML}"
  echo "==> VM ready."
  echo "    Enter with:  $(basename "$0") shell"
  echo "    Inside the VM, your project is mounted at:"
  echo "      /Users/.../$(basename "${PROJECT_ROOT}")"
}

case "${1:-usage}" in
  up)       up ;;
  shell)    lima --name "${VM_NAME}" shell ;;
  ssh)      shift; lima --name "${VM_NAME}" shell "$@" ;;
  status)   lima --name "${VM_NAME}" status ;;
  stop)     lima --name "${VM_NAME}" stop ;;
  delete)   lima --name "${VM_NAME}" delete ;;
  *)
    grep -E '^#   |^#    ' "$0" | sed 's/^#   //; s/^#    //'
    ;;
esac