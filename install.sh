#!/usr/bin/env bash
# AgentGuard install.sh — Phase 4.1
# Step 1: detect platform.
# Step 2: Linux native install from GitHub Releases.
# Step 3: macOS Colima/Docker.
# Step 4: host binary → /usr/local/bin/agentguard.
# Step 5: agentguard doctor (does not abort install).
set -euo pipefail

REPO="agentguard-hq/AgentGuard"
VERSION="${AGENTGUARD_VERSION:-latest}"

WITH_DOCKER=0
for arg in "$@"; do
	case "$arg" in
	--with-docker) WITH_DOCKER=1 ;;
	-h | --help)
		echo "Usage: curl -fsSL …/install.sh | bash -s -- [--with-docker]"
		exit 0
		;;
	*)
		echo "unknown argument: $arg" >&2
		exit 1
		;;
	esac
done

OS=$(uname -s)
ARCH=$(uname -m)
case "$ARCH" in
x86_64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*)
	echo "unsupported arch: $ARCH" >&2
	exit 1
	;;
esac

if [ "$VERSION" = latest ]; then
	base="https://github.com/${REPO}/releases/latest/download"
else
	base="https://github.com/${REPO}/releases/download/${VERSION}"
fi

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "need $1 on PATH" >&2
		exit 1
	}
}

docker_ok() {
	command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

start_colima() {
	if [ "$ARCH" = arm64 ]; then
		VM_TYPE=vz
	else
		VM_TYPE=qemu
	fi
	echo "starting colima (--cpu 4 --memory 8 --disk 60 --vm-type=${VM_TYPE})…"
	colima start --cpu 4 --memory 8 --disk 60 --vm-type="$VM_TYPE"
	if ! command -v docker >/dev/null 2>&1; then
		echo "colima started but docker CLI is not on PATH. Install it: brew install docker" >&2
		exit 1
	fi
	i=0
	while [ "$i" -lt 90 ]; do
		if docker_ok; then
			echo "docker is usable"
			return 0
		fi
		i=$((i + 1))
		sleep 2
	done
	echo "docker info still failing after colima start" >&2
	exit 1
}

setup_macos_docker() {
	if docker_ok; then
		echo "docker already usable; skipping Colima"
		return 0
	fi
	if command -v colima >/dev/null 2>&1; then
		start_colima
	elif command -v brew >/dev/null 2>&1; then
		brew install colima docker
		start_colima
	else
		echo "Homebrew not found. Install Homebrew (https://brew.sh) or Colima, then re-run." >&2
		echo "  brew install colima docker && colima start" >&2
		exit 1
	fi
}

# Download $1 from GitHub Releases, verify checksums.txt, install to /usr/local/bin/agentguard.
install_release_binary() {
	asset="$1"
	need_cmd curl
	need_cmd install

	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT

	# Private repos 404 on anonymous /releases/latest/download/. Prefer gh when logged in.
	if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
		if [ "$VERSION" = latest ]; then
			gh release download --repo "$REPO" --dir "$tmp" --pattern "$asset" --pattern checksums.txt
		else
			gh release download "$VERSION" --repo "$REPO" --dir "$tmp" --pattern "$asset" --pattern checksums.txt
		fi
	elif curl -fsSL "$base/$asset" -o "$tmp/$asset" && curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt"; then
		:
	else
		echo "failed to download $base/$asset" >&2
		echo "If the repo is private, install GitHub CLI and run: gh auth login" >&2
		exit 1
	fi
	(cd "$tmp" && grep " $asset\$" checksums.txt | sha256sum -c -)

	dest=/usr/local/bin/agentguard
	if [ -w /usr/local/bin ] || [ "$(id -u)" -eq 0 ]; then
		install -m 755 "$tmp/$asset" "$dest"
	else
		need_cmd sudo
		sudo install -m 755 "$tmp/$asset" "$dest"
	fi

	echo "installed $dest"
	"$dest" version

	if ! "$dest" doctor; then
		echo "doctor reported failures (expected before: agentguard init)."
		if [ "$OS" = Darwin ]; then
			echo "On Mac, run agents via: agentguard up"
		fi
	fi
}

install_linux() {
	echo "detected: os=Linux arch=${ARCH} with_docker=${WITH_DOCKER}"

	if [ "$WITH_DOCKER" -eq 1 ]; then
		if docker_ok; then
			echo "docker already usable"
		else
			echo "Docker is not usable. Install Docker Engine, then retry." >&2
			echo "https://docs.docker.com/engine/install/" >&2
			exit 1
		fi
	fi

	install_release_binary "agentguard-linux-${ARCH}"

	cat <<'EOF'

Next:
  cd <project>
  agentguard init
  agentguard init --claude   # optional, Claude Code deny text in chat
  agentguard init --codex    # optional, Codex deny text in chat
  sudo agentguard -- claude
EOF
}

install_macos() {
	echo "detected: os=Darwin arch=${ARCH} with_docker=${WITH_DOCKER}"
	setup_macos_docker
	install_release_binary "agentguard-darwin-${ARCH}"

	cat <<'EOF'

Next:
  agentguard login
  cd <project>
  agentguard init
  agentguard init --claude   # optional, Claude Code deny text in chat
  agentguard init --codex    # optional, Codex deny text in chat
  agentguard up
  # inside, first machine only (persists under ~/.agentguard/runtime):
  curl -fsSL https://claude.ai/install.sh | bash
  curl -fsSL https://chatgpt.com/codex/install.sh | sh
  sudo agentguard -- claude    # or: sudo agentguard -- codex
EOF
}

case "$OS" in
Linux)
	install_linux
	;;
Darwin)
	install_macos
	;;
*)
	echo "unsupported OS: $OS (on Windows use WSL2 Ubuntu, then this script)" >&2
	exit 1
	;;
esac
