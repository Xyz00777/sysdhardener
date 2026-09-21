#!/usr/bin/env bash
# scripts/provision-ref-vm.sh
#
# Provision the reference VM reproducibly: download the official
# Ubuntu cloud image, verify its SHA256, build a NoCloud cloud-init
# seed, and define/start it under the user's libvirt session
# (QEMU/KVM). The SSH key is generated fresh each run (secret-free;
# never committed).
#
# Usage: bash scripts/provision-ref-vm.sh [DIR]
#   DIR   working directory for the image + seed (default: /tmp/sysdhardener-refvm)
#
# Requires (host capabilities, not Nix-supplied):
#   - /dev/kvm + libvirt session daemon (virsh qemu:///session)
#   - xorriso (ISO seed), curl, sha256sum
#   - qemu-system-x86_64 (emulator)
#
# Outputs: the domain `sysdhardener-ref` running with ssh on 127.0.0.1:2222.

set -euo pipefail

WORK="${1:-/tmp/sysdhardener-refvm}"
RELEASE="resolute"                 # Ubuntu 26.04 LTS codename
IMAGE_URL="https://cloud-images.ubuntu.com/releases/${RELEASE}/release/ubuntu-26.04-server-cloudimg-amd64.img"
SHA256_SUMS_URL="https://cloud-images.ubuntu.com/releases/${RELEASE}/release/SHA256SUMS"
IMAGE="${WORK}/ubuntu-26.04-server-cloudimg-amd64.img"
SEED_DIR="${WORK}/seed"
SEED_ISO="${WORK}/seed.iso"
KEY="${WORK}/refvm_key"
DOMAIN="sysdhardener-ref"

command -v xorriso >/dev/null 2>&1 || { echo "FAIL: xorriso not on PATH (nix shell nixpkgs#xorriso)" >&2; exit 1; }
command -v virsh  >/dev/null 2>&1 || { echo "FAIL: virsh not on PATH" >&2; exit 1; }
command -v qemu-system-x86_64 >/dev/null 2>&1 || { echo "FAIL: qemu-system-x86_64 not on PATH" >&2; exit 1; }

mkdir -p "${WORK}"

echo "==> download + verify official Ubuntu ${RELEASE} cloud image"
if [[ ! -f "${IMAGE}" ]]; then
  curl -fSL -o "${IMAGE}" "${IMAGE_URL}"
fi
curl -fsSL "${SHA256_SUMS_URL}" > "${WORK}/SHA256SUMS"
expected="$(grep "ubuntu-26.04-server-cloudimg-amd64.img" "${WORK}/SHA256SUMS" | awk '{print $1}')"
actual="$(sha256sum "${IMAGE}" | awk '{print $1}')"
[[ "${expected}" == "${actual}" ]] || { echo "FAIL: image checksum mismatch; expected ${expected} got ${actual}" >&2; exit 1; }
echo "    checksum verified: ${actual}"

# The verified image is the pristine base; never mutate it. Copy it to a
# working disk that the VM boots (booting in-place turns the raw image into
# qcow2, which breaks the checksum for any later re-provision).
DISK="${WORK}/sysdhardener-ref.qcow2"
if [[ ! -f "${DISK}" ]]; then
  qemu-img create -f qcow2 -F raw -b "${IMAGE}" "${DISK}" >/dev/null
fi

echo "==> generate secret-free SSH key"
if [[ ! -f "${KEY}" ]]; then
  ssh-keygen -t ed25519 -N "" -f "${KEY}" -C "sysdhardener-ref-vm" >/dev/null
  chmod 600 "${KEY}"
fi

echo "==> build NoCloud cloud-init seed ISO"
mkdir -p "${SEED_DIR}"
cat > "${SEED_DIR}/user-data" <<EOF
#cloud-config
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat "${KEY}.pub")
ssh_pwauth: false
disable_root: true
package_update: true
packages:
  - linux-tools-generic
  - bpftool
EOF
printf 'instance-id: sysdhardener-ref\nlocal-hostname: sysdhardener-ref\n' > "${SEED_DIR}/meta-data"
xorriso -as mkisofs -o "${SEED_ISO}" -V cidata -J -r "${SEED_DIR}" 2>/dev/null

echo "==> define + start ${DOMAIN} via libvirt session (QEMU/KVM, slirp hostfwd)"
cat > "${WORK}/${DOMAIN}.xml" <<EOF
<domain type='kvm'>
  <name>${DOMAIN}</name>
  <memory unit='KiB'>3145728</memory>
  <vcpu>2</vcpu>
  <os><type arch='x86_64'>hvm</type><boot dev='hd'/></os>
  <features><acpi/></features>
  <devices>
    <emulator>$(command -v qemu-system-x86_64)</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='${DISK}'/>
      <target dev='vda' bus='virtio'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='${SEED_ISO}'/>
      <target dev='sdb' bus='sata'/>
    </disk>
    <controller type='sata' index='0'>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>
    </controller>
    <serial type='pty'><target port='0'/></serial>
    <console type='pty'><target type='serial' port='0'/></console>
  </devices>
  <qemu:commandline xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>
    <qemu:arg value='-netdev'/>
    <qemu:arg value='user,id=user0,hostfwd=tcp:127.0.0.1:2222-:22'/>
    <qemu:arg value='-device'/>
    <qemu:arg value='virtio-net-pci,netdev=user0,id=net0,bus=pci.0,addr=0x7'/>
  </qemu:commandline>
</domain>
EOF

virsh -c qemu:///session undefine "${DOMAIN}" >/dev/null 2>&1 || true
virsh -c qemu:///session define "${WORK}/${DOMAIN}.xml" >/dev/null
virsh -c qemu:///session start "${DOMAIN}" >/dev/null

echo "==> done. SSH: ssh -i ${KEY} -p 2222 ubuntu@127.0.0.1"
echo "    (wait for cloud-init; host keys generated on first boot)"
