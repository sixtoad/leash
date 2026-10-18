#!/usr/bin/env bash
# Boot a disposable KVM guest whose kernel has the BPF LSM active, for the
# release gates of scripts/release.sh (LEASH_RELEASE_GATE_SSH). Used by
# .github/workflows/native-release.yml, whose runners have CONFIG_BPF_LSM=y
# but do not list bpf in the active LSMs.
#
# The guest is the Ubuntu noble cloud image booted directly from its own
# vmlinuz/initrd with lsm=...,bpf on the kernel command line, a NoCloud seed
# carrying an SSH client key and host key generated here (so the host key is
# pinned, never trusted on first use), user-mode networking with SSH forwarded
# to 127.0.0.1, and Docker installed by cloud-init.
#
#   release-gate-vm.sh start <dir>   download, verify, and boot (returns at once)
#   release-gate-vm.sh wait  <dir>   wait for SSH, cloud-init and Docker; prove
#                                    bpf is an active LSM; print the env to use
#   release-gate-vm.sh stop  <dir>   power off the guest
#
# `wait` writes <dir>/env with LEASH_RELEASE_GATE_SSH and
# LEASH_RELEASE_GATE_SSH_CONFIG. Needs qemu-system-x86_64, qemu-img,
# cloud-localds, curl, ssh, ssh-keygen and a usable /dev/kvm.
set -euo pipefail

COMMAND="${1:?usage: release-gate-vm.sh start|wait|stop <dir>}"
DIR="${2:?usage: release-gate-vm.sh start|wait|stop <dir>}"
IMAGE_BASE="${LEASH_GATE_VM_IMAGE_BASE:-https://cloud-images.ubuntu.com/noble/current}"
SSH_PORT="${LEASH_GATE_VM_SSH_PORT:-2222}"
VM_CPUS="${LEASH_GATE_VM_CPUS:-4}"
VM_MEMORY="${LEASH_GATE_VM_MEMORY:-6144}"
LSM_LIST="lockdown,capability,landlock,yama,apparmor,bpf"
HOST_ALIAS=leash-release-gate

log() { printf '%s\n' "release-gate-vm: $*" >&2; }
die() { log "$*"; exit 1; }

download_verified() {
  local base="$1" name="$2" sums="$3" expected
  expected="$(awk -v n="$name" '{f=$2; sub(/^\*/, "", f); if (f == n) print $1}' "$sums")"
  [ -n "$expected" ] || die "no checksum for $name in $base/SHA256SUMS"
  if [ ! -s "$DIR/$name" ] || ! printf '%s  %s\n' "$expected" "$DIR/$name" | sha256sum -c --quiet - 2>/dev/null; then
    log "downloading $base/$name"
    curl -fsSL --retry 5 --retry-delay 5 -o "$DIR/$name.part" "$base/$name"
    mv "$DIR/$name.part" "$DIR/$name"
  fi
  printf '%s  %s\n' "$expected" "$DIR/$name" | sha256sum -c --quiet - || die "$name checksum mismatch"
}


start() {
  mkdir -p "$DIR"
  [ -r /dev/kvm ] && [ -w /dev/kvm ] || die "/dev/kvm is not usable by $(id -un)"
  local image=noble-server-cloudimg-amd64.img
  local kernel=noble-server-cloudimg-amd64-vmlinuz-generic
  local initrd=noble-server-cloudimg-amd64-initrd-generic
  [ "$(uname -m)" = x86_64 ] || die "only x86_64 build hosts are supported"

  curl -fsSL --retry 5 -o "$DIR/SHA256SUMS" "$IMAGE_BASE/SHA256SUMS"
  curl -fsSL --retry 5 -o "$DIR/SHA256SUMS.unpacked" "$IMAGE_BASE/unpacked/SHA256SUMS"
  download_verified "$IMAGE_BASE" "$image" "$DIR/SHA256SUMS"
  download_verified "$IMAGE_BASE/unpacked" "$kernel" "$DIR/SHA256SUMS.unpacked"
  download_verified "$IMAGE_BASE/unpacked" "$initrd" "$DIR/SHA256SUMS.unpacked"

  rm -f "$DIR/id_ed25519" "$DIR/id_ed25519.pub" "$DIR/host_ed25519" "$DIR/host_ed25519.pub"
  ssh-keygen -q -t ed25519 -N '' -C leash-release-gate-client -f "$DIR/id_ed25519"
  ssh-keygen -q -t ed25519 -N '' -C leash-release-gate-host -f "$DIR/host_ed25519"

  {
    printf '%s\n' '#cloud-config' 'ssh_pwauth: false' 'disable_root: true'
    printf '%s\n' 'users:' '  - name: ubuntu' '    sudo: ALL=(ALL) NOPASSWD:ALL' '    shell: /bin/bash' '    ssh_authorized_keys:'
    printf '      - %s\n' "$(cat "$DIR/id_ed25519.pub")"
    printf '%s\n' 'ssh_deletekeys: true' 'ssh_keys:' '  ed25519_private: |'
    sed 's/^/    /' "$DIR/host_ed25519"
    printf '  ed25519_public: %s\n' "$(cat "$DIR/host_ed25519.pub")"
    # Classic image store, like the runner's Docker: a dry run's manager is
    # addressed by its local image ID, which must survive docker save/load.
    printf '%s\n' 'write_files:' '  - path: /etc/docker/daemon.json' '    content: |' '      {"features": {"containerd-snapshotter": false}}'
    printf '%s\n' 'package_update: true' 'packages:' '  - docker.io' '  - git' '  - python3' '  - ca-certificates'
    printf '%s\n' 'runcmd:' '  - [usermod, -aG, docker, ubuntu]' '  - [systemctl, enable, --now, docker]'
  } >"$DIR/user-data"
  printf 'instance-id: leash-release-gate-%s\nlocal-hostname: leash-release-gate\n' "$(date +%s)" >"$DIR/meta-data"
  cloud-localds "$DIR/seed.img" "$DIR/user-data" "$DIR/meta-data"

  rm -f "$DIR/disk.qcow2"
  qemu-img create -q -f qcow2 -F qcow2 -b "$DIR/$image" "$DIR/disk.qcow2" 40G

  printf '[127.0.0.1]:%s %s\n' "$SSH_PORT" "$(cut -d' ' -f1-2 "$DIR/host_ed25519.pub")" >"$DIR/known_hosts"
  cat >"$DIR/ssh_config" <<EOF
Host $HOST_ALIAS
  HostName 127.0.0.1
  Port $SSH_PORT
  User ubuntu
  IdentityFile $DIR/id_ed25519
  IdentitiesOnly yes
  UserKnownHostsFile $DIR/known_hosts
  StrictHostKeyChecking yes
  LogLevel ERROR
  ConnectTimeout 10
EOF

  log "booting noble guest with lsm=$LSM_LIST ($VM_CPUS vCPU, ${VM_MEMORY}M)"
  qemu-system-x86_64 \
    -machine q35,accel=kvm -cpu host -smp "$VM_CPUS" -m "$VM_MEMORY" \
    -kernel "$DIR/$kernel" -initrd "$DIR/$initrd" \
    -append "root=LABEL=cloudimg-rootfs ro console=ttyS0 lsm=$LSM_LIST" \
    -drive "file=$DIR/disk.qcow2,if=virtio,format=qcow2" \
    -drive "file=$DIR/seed.img,if=virtio,format=raw" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" \
    -device virtio-net-pci,netdev=net0 \
    -display none -monitor none -serial "file:$DIR/console.log" \
    -daemonize -pidfile "$DIR/qemu.pid"
}

gate_ssh() { ssh -F "$DIR/ssh_config" -o BatchMode=yes "$HOST_ALIAS" "$@"; }

wait_ready() {
  local deadline=$((SECONDS + ${LEASH_GATE_VM_BOOT_TIMEOUT:-900})) lsm
  log "waiting for SSH..."
  until gate_ssh true 2>/dev/null; do
    [ -f "$DIR/qemu.pid" ] && kill -0 "$(cat "$DIR/qemu.pid")" 2>/dev/null || {
      tail -50 "$DIR/console.log" >&2 || true
      die "guest exited before SSH came up"
    }
    [ "$SECONDS" -lt "$deadline" ] || { tail -50 "$DIR/console.log" >&2 || true; die "timed out waiting for SSH"; }
    sleep 5
  done
  log "waiting for cloud-init..."
  # Exit 2 is "done with recoverable errors" (e.g. schema warnings); the
  # Docker and LSM checks below decide whether the guest is usable.
  local rc=0
  gate_ssh 'cloud-init status --wait >/dev/null' || rc=$?
  gate_ssh 'cloud-init status --long' >&2 || true
  case "$rc" in
    0) ;;
    2) gate_ssh 'sudo cloud-init schema --system' >&2 || true ;;
    *)
      gate_ssh 'sudo tail -80 /var/log/cloud-init-output.log' >&2 || true
      die "cloud-init failed (status $rc)"
      ;;
  esac
  # A fresh session picks up the docker group added by cloud-init.
  until gate_ssh 'docker info --format "docker {{.ServerVersion}} storage {{.Driver}}"' >&2; do
    [ "$SECONDS" -lt "$deadline" ] || die "timed out waiting for Docker"
    sleep 5
  done
  lsm="$(gate_ssh cat /sys/kernel/security/lsm)"
  log "guest kernel $(gate_ssh uname -r), active LSMs: $lsm"
  case ",$lsm," in
    *,bpf,*) ;;
    *) die "bpf is not an active LSM in the guest" ;;
  esac
  {
    printf 'LEASH_RELEASE_GATE_SSH=%s\n' "$HOST_ALIAS"
    printf 'LEASH_RELEASE_GATE_SSH_CONFIG=%s\n' "$DIR/ssh_config"
  } | tee "$DIR/env"
}

stop() {
  if [ -f "$DIR/qemu.pid" ]; then
    local pid
    pid="$(cat "$DIR/qemu.pid")"
    gate_ssh 'sudo systemctl poweroff' >/dev/null 2>&1 || true
    for _ in $(seq 1 30); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 1
    done
    kill "$pid" 2>/dev/null || true
    rm -f "$DIR/qemu.pid"
  fi
}

case "$COMMAND" in
  start) start ;;
  wait) wait_ready ;;
  stop) stop ;;
  *) die "unknown command $COMMAND" ;;
esac
