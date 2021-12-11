#!/usr/bin/env bash

set -ex

mkdir -p tmp/ out/

if [ ! -d "tmp/linux" ]; then
	git clone https://github.com/torvalds/linux.git tmp/linux
fi

if [ ! -f "tmp/linux/arch/x86/boot/bzImage" ]; then
	cp circe_initramfs/kernel-config tmp/linux/.config
	pushd tmp/linux/
	git checkout 6f513529296fd4f696afb4354c46508abe646541
	make -j$(nproc)
	popd
fi

mkdir -p out/
cp tmp/linux/arch/x86/boot/bzImage out/kernel-image

echo "The output is available at out/kernel-image"
