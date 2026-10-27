#!/bin/sh
# Run the test suite with BusyBox ash (the router's shell) inside Alpine.
#   scripts/test-busybox.sh
set -eu
cd "$(dirname "$0")/.."
docker run --rm -v "$PWD":/src:ro python:3.12-alpine sh -euc '
	apk add -q --no-cache jq >/dev/null
	pip install -q --root-user-action=ignore pytest pytest-xdist >/dev/null 2>&1
	mkdir /work
	cp -r /src/files /src/tests /src/pyproject.toml /work/
	cd /work
	echo "shell: $(readlink -f /bin/sh)"
	WD_TEST_SHELL=sh python -m pytest -q -n 8 -p no:cacheprovider
'
