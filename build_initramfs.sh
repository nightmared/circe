#!/usr/bin/env bash

set -ex

export PKG_CONFIG_ALLOW_CROSS=true
BUILD_PROFILE=debug

CARGO_ARGS=""
[ ${BUILD_PROFILE} = "release" ] && CARGO_ARGS="--release ${CARGO_ARGS}"
cargo rustc -p circe_initramfs ${CARGO_ARGS} -- -C target-feature=+crt-static

mkdir -p tmp/

if [ ! -d "tmp/busybox" ]; then
	git clone -b 1_34_stable https://github.com/mirror/busybox.git tmp/busybox
fi

if [ ! -f "tmp/busybox/_install/bin/busybox" ]; then
	cp circe_initramfs/busybox-config tmp/busybox/.config
	pushd tmp/busybox/
	make -j$(nproc)
	make install
	popd
fi


rm -rf out/initramfs
mkdir -p out/initramfs
cp -r tmp/busybox/_install/{bin,sbin} out/initramfs/
cp target/${BUILD_PROFILE}/circe_initramfs out/initramfs/init

pushd out/initramfs/
find . | cpio --create --format=newc > ../initramfs.cpio
popd

echo "The output is available at out/initramfs.cpio"
