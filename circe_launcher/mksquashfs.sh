#!/usr/bin/env bash

set -x

image_name="$1"
dest_file="$2"

mount_dir=$(podman image mount "${image_name}")
if [ $? -ne 0 ]; then
	echo "Could mount the image"
	exit 1
fi
mksquashfs "${mount_dir}" "${dest_file}" -noInodeCompression -noIdTableCompression -noDataCompression -noFragmentCompression -noXattrCompression
