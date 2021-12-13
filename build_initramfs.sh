#!/usr/bin/env bash

set -ex

export PKG_CONFIG_ALLOW_CROSS=true
cargo rustc -p circe_initramfs --release --target=x86_64-unknown-linux-musl -- -C target-feature=+crt-static

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
cp target/x86_64-unknown-linux-musl/release/circe_initramfs out/initramfs/init

pushd out/initramfs/
find . | cpio --create --format=newc > ../initramfs.cpio
popd

echo "The output is available at out/initramfs.cpio"
