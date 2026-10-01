#!/usr/bin/env bash
# Scans the object files of a SwiftPM scratch directory for the
# `-lFoundationNetworking` autolink entry Swift records for any module that
# imports FoundationNetworking, and exits 1 if one is found (or 0 if --expect
# is given and one is). A module that carries the entry puts
# libFoundationNetworking.so in the NEEDED list of whatever links it.
#
# usage: scan-foundation-networking.sh [--expect] <scratch-path>
set -euo pipefail

expect=false
if [[ "${1:-}" == "--expect" ]]; then
	expect=true
	shift
fi
scratch="${1:?usage: $0 [--expect] <scratch-path>}"

objects=()
while IFS= read -r -d '' object; do
	objects+=("$object")
done < <(find "$scratch" -name '*.o' -path '*android*' -print0)

if [[ ${#objects[@]} -eq 0 ]]; then
	echo "error: no Android object files under $scratch; nothing was scanned" >&2
	exit 2
fi

hits=()
for object in "${objects[@]}"; do
	if strings "$object" | grep -- '-lFoundationNetworking' >/dev/null; then
		hits+=("$object")
	fi
done

if $expect; then
	if [[ ${#hits[@]} -eq 0 ]]; then
		echo "error: expected a FoundationNetworking autolink entry but found none (scanner is not detecting it)" >&2
		exit 1
	fi
	echo "ok: scanner detects FoundationNetworking in ${#hits[@]} of ${#objects[@]} objects"
else
	if [[ ${#hits[@]} -gt 0 ]]; then
		echo "error: FoundationNetworking is linked by:" >&2
		printf '  %s\n' "${hits[@]}" >&2
		exit 1
	fi
	echo "ok: none of ${#objects[@]} objects link FoundationNetworking"
fi
