
# Ensure linux-yocto-fitimage is deployed before do_generate_static_tar.
# The upstream image_types_phosphor.bbclass adds this dep to do_generate_static
# but omits it from do_generate_static_tar, creating a race on fresh builds.
do_generate_static_tar[depends] += "${@'linux-yocto-fitimage:do_deploy' if d.getVar('INITRAMFS_IMAGE') else ''}"

# Additional packages for johnblue QEMU development image.
# We add our recipe https-guard-openbmc here
IMAGE_INSTALL:append = " https-guard-openbmc"
DISTRO_FEATURES:append = " systemd"
