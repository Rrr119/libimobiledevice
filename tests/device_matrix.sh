#!/bin/sh
#
# Exercise pcapd against three connected device classes: iPhone, iPad, iPod.
#
# Usage:
#   tests/device_matrix.sh UDID_IPHONE UDID_IPAD UDID_IPOD [OUTPUT_DIR]
#
# Set IDEVICEPCAP to the built tool path if it is not in PATH.

set -eu

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
	echo "Usage: $0 UDID_IPHONE UDID_IPAD UDID_IPOD [OUTPUT_DIR]" >&2
	exit 2
fi

IPHONE_UDID=$1
IPAD_UDID=$2
IPOD_UDID=$3
OUTPUT_DIR=${4:-./device-matrix-results}
IDEVICEPCAP=${IDEVICEPCAP:-idevicepcap}
IDEVICEINFO=${IDEVICEINFO:-ideviceinfo}
IDEVICEPAIR=${IDEVICEPAIR:-idevicepair}

mkdir -p "$OUTPUT_DIR"

run_device() {
	model=$1
	udid=$2
	product_type=$("$IDEVICEINFO" -u "$udid" -k ProductType)

	case "$product_type" in
		iPhone*) actual=iPhone ;;
		iPad*) actual=iPad ;;
		iPod*) actual=iPod ;;
		*) actual=other ;;
	esac

	if [ "$actual" != "$model" ]; then
		echo "ERROR: $udid reports ProductType=$product_type, expected $model" >&2
		return 1
	fi

	"$IDEVICEPAIR" -u "$udid" validate >/dev/null 2>&1 || "$IDEVICEPAIR" -u "$udid" pair

	output="$OUTPUT_DIR/$model.pcapng"
	"$IDEVICEPCAP" -u "$udid" -P -c 3 -o "$output"

	test -s "$output"
	if ! od -An -tx1 -N4 "$output" | grep -q '0a 0d 0d 0a'; then
		echo "ERROR: $output is not a PCAPNG file" >&2
		return 1
	fi

	echo "PASS: $model ($product_type) -> $output"
}

run_device iPhone "$IPHONE_UDID"
run_device iPad "$IPAD_UDID"
run_device iPod "$IPOD_UDID"

echo "All three device classes passed."
