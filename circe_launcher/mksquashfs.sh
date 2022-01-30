#!/usr/bin/env bash

image_name="$1"
dest_file="$2"
json_location="$3"

mount_dir=$(podman image mount "${image_name}")
if [ $? -ne 0 ]; then
	echo "Couldn't mount the image, aborting..."
	exit 1
fi

temp_dir="$(mktemp -d)"
cp "${json_location}" "${temp_dir}/circe_container_config.json"

[ -f "${dest_file}" ] && rm "${dest_file}"
mksquashfs "${mount_dir}"/* "${temp_dir}/circe_container_config.json" "${dest_file}" -noInodeCompression -noIdTableCompression -noDataCompression -noFragmentCompression -noXattrCompression -no-recovery

# cleanup
rm -rf "${temp_dir}"
