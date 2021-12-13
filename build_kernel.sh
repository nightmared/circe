#!/usr/bin/env bash

set -ex

mkdir -p tmp/ out/

if [ ! -d "tmp/linux" ]; then
	git clone https://github.com/torvalds/linux.git tmp/linux
fi

if [ ! -f "tmp/linux/arch/x86/boot/bzImage" ]; then
	cp circe_initramfs/kernel-config tmp/linux/.config
	pushd tmp/linux/
	git fetch
	git checkout a763d5a5abd65797aec3dd1bf01fe2ccbec32967
	make -j$(nproc)
	popd
fi

mkdir -p out/
cp tmp/linux/arch/x86/boot/bzImage out/kernel-image

echo "The output is available at out/kernel-image"
