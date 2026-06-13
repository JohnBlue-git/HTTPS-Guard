# =============================================================================
# Kernel configuration for HTTPS-Guard eBPF/XDP support
#
# This bbappend adds the bpf-kernel-config.cfg fragment to the linux-aspeed
# kernel build, enabling the BPF, XDP, uprobe, and tracing features required
# by the https-guardd daemon. The config fragment lives alongside this
# bbappend in recipes-kernel/linux/.
#
# After building, verify the kernel config includes these with:
#   bitbake virtual/kernel -c menuconfig
#   grep -E "CONFIG_BPF|CONFIG_XDP|CONFIG_UPROBE" .config
# =============================================================================

FILESEXTRAPATHS:prepend := "${THISDIR}:"

SRC_URI += " \
    file://bpf-kernel-config.cfg \
"

KERNEL_CONFIG_FRAGMENTS += " \
    bpf-kernel-config.cfg \
"