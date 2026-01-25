#!/bin/bash
#
# Houndoom Installation Script
# Usage: curl -sSL https://raw.githubusercontent.com/IvanShishkin/houndoom/main/install.sh | bash
#        wget -qO- https://raw.githubusercontent.com/IvanShishkin/houndoom/main/install.sh | bash

set -e

REPO="IvanShishkin/houndoom"
BINARY_NAME="houndoom"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
INSTALL_DIR=""
VERSION=""
NO_SUDO=false

# Print colored message
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Show usage
usage() {
    echo "Houndoom Installation Script"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --version=X.X.X    Install specific version (default: latest)"
    echo "  --dir=/path        Custom installation directory"
    echo "  --no-sudo          Install to ~/.local/bin without sudo"
    echo "  -h, --help         Show this help message"
    echo ""
    echo "Examples:"
    echo "  curl -sSL https://raw.githubusercontent.com/IvanShishkin/houndoom/main/install.sh | bash"
    echo "  curl -sSL .../install.sh | bash -s -- --version=1.0.0"
    echo "  curl -sSL .../install.sh | bash -s -- --no-sudo"
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --version=*)
                VERSION="${1#*=}"
                shift
                ;;
            --dir=*)
                INSTALL_DIR="${1#*=}"
                shift
                ;;
            --no-sudo)
                NO_SUDO=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                ;;
        esac
    done
}

# Detect OS
detect_os() {
    local os
    os=$(uname -s | tr '[:upper:]' '[:lower:]')

    case "$os" in
        linux*)
            echo "linux"
            ;;
        *)
            print_error "This installer only supports Linux."
            print_error "Detected OS: $os"
            exit 1
            ;;
    esac
}

# Detect architecture
detect_arch() {
    local arch
    arch=$(uname -m)

    case "$arch" in
        x86_64|amd64)
            echo "amd64"
            ;;
        aarch64|arm64)
            echo "arm64"
            ;;
        *)
            print_error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
}

# Get latest version from GitHub API
get_latest_version() {
    local latest_url="https://api.github.com/repos/${REPO}/releases/latest"
    local version

    if command -v curl &> /dev/null; then
        version=$(curl -sL "$latest_url" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    elif command -v wget &> /dev/null; then
        version=$(wget -qO- "$latest_url" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    else
        print_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi

    if [ -z "$version" ]; then
        print_error "Failed to get latest version. Check your internet connection."
        exit 1
    fi

    echo "$version"
}

# Download file
download_file() {
    local url=$1
    local output=$2

    print_info "Downloading from $url"

    if command -v curl &> /dev/null; then
        curl -sL -o "$output" "$url"
    elif command -v wget &> /dev/null; then
        wget -qO "$output" "$url"
    else
        print_error "Neither curl nor wget found."
        exit 1
    fi
}

# Verify checksum
verify_checksum() {
    local file=$1
    local checksums_file=$2
    local expected_file=$3

    if command -v sha256sum &> /dev/null; then
        local actual
        actual=$(sha256sum "$file" | awk '{print $1}')
        local expected
        expected=$(grep "$expected_file" "$checksums_file" | awk '{print $1}')

        if [ "$actual" != "$expected" ]; then
            print_error "Checksum verification failed!"
            print_error "Expected: $expected"
            print_error "Actual:   $actual"
            exit 1
        fi
        print_success "Checksum verified"
    elif command -v shasum &> /dev/null; then
        local actual
        actual=$(shasum -a 256 "$file" | awk '{print $1}')
        local expected
        expected=$(grep "$expected_file" "$checksums_file" | awk '{print $1}')

        if [ "$actual" != "$expected" ]; then
            print_error "Checksum verification failed!"
            exit 1
        fi
        print_success "Checksum verified"
    else
        print_warning "sha256sum/shasum not found, skipping checksum verification"
    fi
}

# Determine installation directory
get_install_dir() {
    if [ -n "$INSTALL_DIR" ]; then
        echo "$INSTALL_DIR"
        return
    fi

    if [ "$NO_SUDO" = true ]; then
        echo "$HOME/.local/bin"
    else
        echo "/usr/local/bin"
    fi
}

# Install binary
install_binary() {
    local src=$1
    local dest=$2
    local install_dir
    install_dir=$(dirname "$dest")

    # Create directory if it doesn't exist
    if [ ! -d "$install_dir" ]; then
        print_info "Creating directory $install_dir"
        if [ "$NO_SUDO" = true ] || [ -w "$(dirname "$install_dir")" ]; then
            mkdir -p "$install_dir"
        else
            sudo mkdir -p "$install_dir"
        fi
    fi

    # Install binary
    print_info "Installing to $dest"
    if [ "$NO_SUDO" = true ] || [ -w "$install_dir" ]; then
        cp "$src" "$dest"
        chmod +x "$dest"
    else
        sudo cp "$src" "$dest"
        sudo chmod +x "$dest"
    fi
}

# Check if directory is in PATH
check_path() {
    local dir=$1

    if [[ ":$PATH:" != *":$dir:"* ]]; then
        print_warning "$dir is not in your PATH"
        echo ""
        echo "Add it to your PATH by running:"
        echo ""
        if [[ "$SHELL" == *"zsh"* ]]; then
            echo "  echo 'export PATH=\"$dir:\$PATH\"' >> ~/.zshrc"
            echo "  source ~/.zshrc"
        else
            echo "  echo 'export PATH=\"$dir:\$PATH\"' >> ~/.bashrc"
            echo "  source ~/.bashrc"
        fi
        echo ""
    fi
}

# Main installation function
main() {
    parse_args "$@"

    echo ""
    echo "  _   _                       _                        "
    echo " | | | | ___  _   _ _ __   __| | ___   ___  _ __ ___   "
    echo " | |_| |/ _ \| | | | '_ \ / _\` |/ _ \ / _ \| '_ \` _ \  "
    echo " |  _  | (_) | |_| | | | | (_| | (_) | (_) | | | | | | "
    echo " |_| |_|\___/ \__,_|_| |_|\__,_|\___/ \___/|_| |_| |_| "
    echo ""
    echo " Security Scanner Installer"
    echo ""

    # Detect platform
    local os
    os=$(detect_os)
    local arch
    arch=$(detect_arch)
    print_info "Detected platform: ${os}/${arch}"

    # Get version
    if [ -z "$VERSION" ]; then
        print_info "Fetching latest version..."
        VERSION=$(get_latest_version)
    fi
    print_info "Version: $VERSION"

    # Build download URL
    local version_num="${VERSION#v}"
    local archive_name="${BINARY_NAME}-${VERSION}-${os}-${arch}.tar.gz"
    local download_url="https://github.com/${REPO}/releases/download/${VERSION}/${archive_name}"
    local checksums_url="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

    # Create temp directory
    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap "rm -rf $tmp_dir" EXIT

    # Download archive
    local archive_path="${tmp_dir}/${archive_name}"
    download_file "$download_url" "$archive_path"

    # Download and verify checksums
    local checksums_path="${tmp_dir}/checksums.txt"
    download_file "$checksums_url" "$checksums_path"
    verify_checksum "$archive_path" "$checksums_path" "$archive_name"

    # Extract archive
    print_info "Extracting archive..."
    tar -xzf "$archive_path" -C "$tmp_dir"

    # Find the binary (might be in a subdirectory)
    local binary_src="${tmp_dir}/${BINARY_NAME}"
    if [ ! -f "$binary_src" ]; then
        binary_src="${tmp_dir}/${BINARY_NAME}/${BINARY_NAME}"
    fi

    if [ ! -f "$binary_src" ]; then
        print_error "Binary not found in archive"
        exit 1
    fi

    # Install binary
    local install_dir
    install_dir=$(get_install_dir)
    local binary_path="${install_dir}/${BINARY_NAME}"
    install_binary "$binary_src" "$binary_path"

    # Check PATH
    check_path "$install_dir"

    # Verify installation
    echo ""
    if command -v "$BINARY_NAME" &> /dev/null; then
        print_success "Houndoom ${VERSION} installed successfully!"
        echo ""
        "$BINARY_NAME" --version 2>/dev/null || true
    else
        print_success "Houndoom ${VERSION} installed to ${binary_path}"
        print_info "Run '${binary_path} --help' to get started"
    fi

    echo ""
    print_info "Quick start:"
    echo "  houndoom scan /path/to/website"
    echo "  houndoom scan /path --mode=paranoid"
    echo "  houndoom --help"
    echo ""
}

main "$@"
