#!/usr/bin/env sh
set -eu

REPO="safe-agentic-world/nomos"
VERSION="${NOMOS_VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

detect_os() {
  case "$(uname -s)" in
    Linux)
      printf '%s' "linux"
      ;;
    Darwin)
      printf '%s' "darwin"
      ;;
    *)
      echo "Unsupported operating system: $(uname -s)" >&2
      exit 1
      ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)
      printf '%s' "amd64"
      ;;
    arm64|aarch64)
      printf '%s' "arm64"
      ;;
    *)
      echo "Unsupported architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

download() {
  url="$1"
  output="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$output"
    return
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -qO "$output" "$url"
    return
  fi
  echo "curl or wget is required" >&2
  exit 1
}

verify_checksum() {
  archive="$1"
  checksums="$2"
  asset_name="$3"
  expected="$(awk -v target="$asset_name" '$2 == target { print $1 }' "$checksums")"
  if [ -z "$expected" ]; then
    echo "Missing checksum for ${asset_name}" >&2
    exit 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$archive" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
  fi
  if [ "$expected" != "$actual" ]; then
    echo "Checksum verification failed for ${asset_name}" >&2
    exit 1
  fi
}

os_name="$(detect_os)"
arch_name="$(detect_arch)"
asset_name="nomos-${os_name}-${arch_name}.tar.gz"

if [ "$VERSION" = "latest" ]; then
  base_url="https://github.com/${REPO}/releases/latest/download"
else
  base_url="https://github.com/${REPO}/releases/download/${VERSION}"
fi

need_cmd tar
need_cmd mktemp
need_cmd grep
need_cmd awk
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  echo "sha256sum or shasum is required" >&2
  exit 1
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT INT TERM

archive_path="${workdir}/${asset_name}"
checksums_path="${workdir}/nomos-checksums.txt"

download "${base_url}/${asset_name}" "$archive_path"
download "${base_url}/nomos-checksums.txt" "$checksums_path"
verify_checksum "$archive_path" "$checksums_path" "$asset_name"

tar -xzf "$archive_path" -C "$workdir"

binary_path="${workdir}/nomos"
if [ ! -f "$binary_path" ]; then
  echo "Archive did not contain nomos" >&2
  exit 1
fi

if [ ! -d "$INSTALL_DIR" ]; then
  mkdir -p "$INSTALL_DIR"
fi

cp "$binary_path" "${INSTALL_DIR}/nomos"
chmod 0755 "${INSTALL_DIR}/nomos"

echo "Installed nomos to ${INSTALL_DIR}/nomos"
case ":${PATH:-}:" in
  *:"${INSTALL_DIR}":*)
    ;;
  *)
    echo "Add ${INSTALL_DIR} to PATH to use 'nomos' directly."
    ;;
esac
