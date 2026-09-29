#!/usr/bin/env bash
# CI helper: go-public needs git 2.44 or newer. Print the runner's git version and, when it is
# older, install a current one (the git-core PPA on Linux, Homebrew on macOS). Fail if it is
# still older.
set -euo pipefail

need_major=2
need_minor=44

version_ok() {
  local raw major minor
  raw=$(git --version | sed -E 's/^git version ([0-9]+)\.([0-9]+).*/\1 \2/')
  read -r major minor <<<"$raw"
  [ "$major" -gt "$need_major" ] || { [ "$major" -eq "$need_major" ] && [ "$minor" -ge "$need_minor" ]; }
}

git --version
if ! version_ok; then
  case "$(uname -s)" in
    Linux)
      sudo add-apt-repository -y ppa:git-core/ppa
      sudo apt-get update
      sudo apt-get install -y git
      ;;
    Darwin)
      brew install git
      hash -r
      ;;
  esac
  git --version
  version_ok || { echo "git ${need_major}.${need_minor} or newer is required" >&2; exit 1; }
fi
