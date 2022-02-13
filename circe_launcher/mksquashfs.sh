#!/usr/bin/env bash

image_name="$1"
dest_file="$2"

mount_dir=$(podman image mount "${image_name}")
if [ $? -ne 0 ]; then
	echo "Couldn't mount the image, aborting..."
	exit 1
fi

[ -f "${dest_file}" ] && rm "${dest_file}"
mksquashfs "${mount_dir}" "${dest_file}" -noInodeCompression -noIdTableCompression -noDataCompression -noFragmentCompression -noXattrCompression -no-recovery
