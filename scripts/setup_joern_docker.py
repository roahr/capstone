#!/usr/bin/env python3
"""
SEC-C Joern Setup via Docker or direct install.

Checks for Joern availability and sets it up using the best available method:
1. Native Joern CLI (if already installed)
2. Docker-based Joern (if Docker is available)
3. Direct download (if Java 11+ is available)

Usage:
    python scripts/setup_joern_docker.py
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def check_native_joern() -> str | None:
    """Check if Joern is natively installed."""
    path = shutil.which("joern")
    if path:
        print(f"  [OK] Joern found natively: {path}")
        try:
            result = subprocess.run(
                ["joern", "--version"], capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                print(f"       Version: {result.stdout.strip()}")
        except Exception:
            pass
        return path
    return None


def check_docker() -> bool:
    """Check if Docker is available."""
    docker = shutil.which("docker")
    if not docker:
        return False
    try:
        result = subprocess.run(
            ["docker", "info"], capture_output=True, text=True, timeout=15
        )
        return result.returncode == 0
    except Exception:
        return False


def check_java() -> int | None:
    """Check Java version. Returns major version or None."""
    java = shutil.which("java")
    if not java:
        return None
    try:
        result = subprocess.run(
            ["java", "-version"], capture_output=True, text=True, timeout=10
        )
        output = result.stderr or result.stdout
        # Parse version from output like: openjdk version "21.0.8"
        import re
        match = re.search(r'"(\d+)', output)
        if match:
            version = int(match.group(1))
            # Handle old-style "1.8" as version 8
            if version == 1:
                match2 = re.search(r'"1\.(\d+)', output)
                if match2:
                    version = int(match2.group(1))
            return version
    except Exception:
        pass
    return None


def setup_docker_joern() -> bool:
    """Set up Joern via Docker."""
    print("\n  --- Docker-based Joern Setup ---\n")
    print("  [>] Pulling Joern Docker image ...")

    try:
        result = subprocess.run(
            ["docker", "pull", "ghcr.io/joernio/joern"],
            capture_output=False, timeout=600,
        )
        if result.returncode != 0:
            print("  [X] Docker pull failed")
            return False
    except Exception as e:
        print(f"  [X] Docker pull error: {e}")
        return False

    print("  [OK] Joern Docker image pulled")

    # Create wrapper script
    wrapper_dir = Path.home() / ".sec-c" / "joern"
    wrapper_dir.mkdir(parents=True, exist_ok=True)

    if platform.system() == "Windows":
        # Batch wrapper for Windows
        wrapper_path = wrapper_dir / "joern.bat"
        wrapper_path.write_text(
            '@echo off\n'
            'docker run --rm -v "%cd%":/code -w /code '
            'ghcr.io/joernio/joern joern %*\n'
        )
        # Also create a bash wrapper for Git Bash
        bash_wrapper = wrapper_dir / "joern"
        bash_wrapper.write_text(
            '#!/bin/bash\n'
            'docker run --rm -v "$(pwd)":/code -w /code '
            'ghcr.io/joernio/joern joern "$@"\n'
        )
    else:
        wrapper_path = wrapper_dir / "joern"
        wrapper_path.write_text(
            '#!/bin/bash\n'
            'docker run --rm -v "$(pwd)":/code -w /code '
            'ghcr.io/joernio/joern joern "$@"\n'
        )
        wrapper_path.chmod(0o755)

    print(f"  [OK] Wrapper script created: {wrapper_path}")
    print(f"\n  Add to PATH: {wrapper_dir}")
    return True


def setup_native_joern() -> bool:
    """Download and install Joern natively (requires Java 11+)."""
    print("\n  --- Native Joern Installation ---\n")

    install_dir = Path.home() / ".sec-c" / "joern"
    install_dir.mkdir(parents=True, exist_ok=True)

    # Download installer
    print("  [>] Downloading Joern installer ...")
    url = "https://github.com/joernio/joern/releases/latest/download/joern-install.sh"

    try:
        import httpx
        response = httpx.get(url, follow_redirects=True, timeout=120)
        installer_path = install_dir / "joern-install.sh"
        installer_path.write_bytes(response.content)
        print(f"      Downloaded: {len(response.content)} bytes")
    except Exception as e:
        print(f"  [X] Download failed: {e}")
        return False

    # Run installer
    print(f"  [>] Installing to {install_dir} ...")
    try:
        result = subprocess.run(
            ["bash", str(installer_path), f"--install-dir={install_dir}"],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode == 0:
            print("  [OK] Joern installed successfully")
            return True
        else:
            print(f"  [!] Installer returned code {result.returncode}")
            print(f"      stderr: {result.stderr[:200]}")
            return False
    except Exception as e:
        print(f"  [X] Installation failed: {e}")
        return False


def main():
    print()
    print("  ================================================================")
    print("  Sec-C Joern Setup")
    print("  ================================================================")
    print()

    # Check 1: Already installed?
    if check_native_joern():
        print("\n  Joern is ready. No setup needed.")
        print("  ================================================================")
        return

    # Check 2: Docker available?
    has_docker = check_docker()
    if has_docker:
        print("  [OK] Docker is available")
    else:
        print("  [--] Docker not available")

    # Check 3: Java available?
    java_version = check_java()
    if java_version and java_version >= 11:
        print(f"  [OK] Java {java_version} detected")
    elif java_version:
        print(f"  [!] Java {java_version} detected (need 11+)")
        java_version = None
    else:
        print("  [--] Java not found")

    print()

    # Decision
    if has_docker:
        print("  Recommended: Docker-based setup (cleanest, no Java dependency)")
        success = setup_docker_joern()
    elif java_version and java_version >= 11:
        print("  Using: Native installation (Java 11+ available)")
        success = setup_native_joern()
    else:
        print("  [X] Cannot install Joern:")
        print("      - Docker not available")
        print("      - Java 11+ not available")
        print()
        print("  Options:")
        print("    1. Install Docker Desktop: https://www.docker.com/products/docker-desktop")
        print("    2. Install Java 11+: https://adoptium.net/")
        print()
        print("  Note: SEC-C works without Joern (Graph stage uses simplified analysis)")
        print("  ================================================================")
        return

    if success:
        wrapper_dir = Path.home() / ".sec-c" / "joern"
        print()
        print("  ================================================================")
        print("  Joern setup complete!")
        print("  ================================================================")
        print(f"  Add to PATH: {wrapper_dir}")
        print()
        if platform.system() == "Windows":
            print("    PowerShell:")
            print(f'    $env:PATH += ";{wrapper_dir}"')
            print()
            print("    Git Bash:")
            print(f'    export PATH="$PATH:{str(wrapper_dir).replace(chr(92), "/")}"')
        else:
            print(f'    export PATH="$PATH:{wrapper_dir}"')
        print()
        print("  Verify: joern --version")
        print("  ================================================================")
    else:
        print()
        print("  [X] Setup failed. SEC-C will use simplified graph analysis.")
        print("  ================================================================")


if __name__ == "__main__":
    main()
