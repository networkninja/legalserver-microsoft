#!/usr/bin/env bash

set -euo pipefail

docker compose run --build --rm legalserver_microsoft "$@"
