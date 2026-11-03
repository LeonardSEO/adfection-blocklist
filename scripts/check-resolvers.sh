#!/usr/bin/env bash
set -euo pipefail
sudo apt-get update -qq
sudo apt-get install -y unbound bind9-utils dnsmasq-base
for file in lists/unbound/*.txt; do unbound-checkconf "$file"; done
for file in lists/rpz/*.txt; do named-checkzone rpz.invalid "$file"; done
for file in lists/dnsmasq/*.txt; do dnsmasq --test --conf-file="$file"; done
