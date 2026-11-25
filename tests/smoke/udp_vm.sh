#!/usr/bin/env bash
# Boot a disposable guest with no disk, shared filesystem, or network adapter.
set -euo pipefail
kernel=${1:?Usage: bash tests/smoke/udp_vm.sh /path/to/vmlinuz-VERSION}
[[ -r "$kernel" ]] || { echo "Cannot read kernel: $kernel" >&2; exit 1; }
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
root=$work/root
mkdir -p "$root"/{dev,proc,sys,run,tmp,usr/bin,test}
copy_binary() {
    local binary=$1 library
    install -Dm755 "$binary" "$root$binary"
    while read -r library; do
        install -Dm755 "$library" "$root$library"
    done < <(ldd "$binary" | awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}' | sort -u)
}

install -m755 "$(command -v busybox)" "$root/usr/bin/busybox"
copy_binary /usr/bin/bpftrace
python=/usr/bin/$(basename "$(readlink -f /usr/bin/python3)")
copy_binary "$python"
ln -s "${python##*/}" "$root/usr/bin/python3"
stdlib=$(/usr/bin/python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')
mkdir -p "$root$(dirname "$stdlib")"
cp -a "$stdlib" "$root$stdlib"
while IFS= read -r -d '' extension; do
    while read -r library; do
        [[ -e "$root$library" ]] || install -Dm755 "$library" "$root$library"
    done < <(ldd "$extension" | awk '/=> \// {print $3}')
done < <(find "$stdlib/lib-dynload" -name '*.so' -print0)
install -m644 "$repo/deploy/udp/"{collector.py,udp.bt} "$repo/tests/smoke/udp_guest.py" "$root/test/"
cat > "$root/init" <<'INIT'
#!/usr/bin/busybox sh
set -e
export PATH=/usr/bin BPFTRACE_COLOR=never PYTHON_COLORS=0
busybox mount -t devtmpfs devtmpfs /dev
busybox mount -t proc proc /proc
busybox ln -s /proc/self/fd /dev/fd
busybox mount -t sysfs sysfs /sys
busybox mount -t tracefs tracefs /sys/kernel/tracing
busybox ip link set lo up
if python3 -B /test/udp_guest.py; then
    echo WATCHDOG_UDP_SMOKE_PASS
else
    echo WATCHDOG_UDP_SMOKE_FAIL
fi
busybox poweroff -f
INIT
chmod +x "$root/init"
(cd "$root" && find . -print0 | cpio --null -o -H newc --quiet | gzip -1 > "$work/initramfs.gz")
timeout 210 qemu-system-x86_64 -machine accel=tcg -cpu max -m 1536 -smp 2 \
    -nodefaults -no-reboot -display none -nic none -serial stdio \
    -kernel "$kernel" -initrd "$work/initramfs.gz" \
    -append 'console=ttyS0 rdinit=/init rootfstype=ramfs panic=-1 quiet lockdown=none' | tee "$work/serial.log"
grep -q '^WATCHDOG_UDP_SMOKE_PASS' "$work/serial.log"
