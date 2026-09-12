#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

GRADLE_VERSION="8.11.1"
TOOLS_DIR="$HERE/.build-tools"
GRADLE_HOME_LOCAL="$TOOLS_DIR/gradle-$GRADLE_VERSION"

java_major() {
  "$1" -version 2>&1 | awk -F '[".]' '/version/ {print ($2=="1" ? $3 : $2); exit}'
}

# AGP 8.10.x needs JDK 17+; Gradle 8.11.1 cannot run on Java 25.
# Prefer a locally installed JDK 17 or 21 when the default Java is too new.
choose_java() {
  local candidates=()
  if [ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME}/bin/java" ]; then
    candidates+=("${JAVA_HOME}")
  fi
  candidates+=(
    "/usr/lib/jvm/java-21-openjdk-amd64"
    "/usr/lib/jvm/java-17-openjdk-amd64"
    "/usr/lib/jvm/java-21-openjdk"
    "/usr/lib/jvm/java-17-openjdk"
  )

  local home major
  for home in "${candidates[@]}"; do
    [ -x "$home/bin/java" ] || continue
    major="$(java_major "$home/bin/java" || true)"
    if [[ "$major" =~ ^[0-9]+$ ]] && [ "$major" -ge 17 ] && [ "$major" -le 23 ]; then
      export JAVA_HOME="$home"
      export PATH="$JAVA_HOME/bin:$PATH"
      return 0
    fi
  done

  if command -v java >/dev/null 2>&1; then
    major="$(java_major "$(command -v java)" || true)"
    if [[ "$major" =~ ^[0-9]+$ ]] && [ "$major" -ge 17 ] && [ "$major" -le 23 ]; then
      return 0
    fi
  fi

  cat >&2 <<'MSG'
A compatible JDK was not found.
This project uses Android Gradle Plugin 8.10.x and Gradle 8.11.1.
Install JDK 17 (recommended), then run this script again:

  sudo apt update
  sudo apt install openjdk-17-jdk

If Kali offers JDK 21 instead, that is also suitable.
MSG
  exit 2
}

version_ge() {
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

gradle_version_of() {
  "$1" --version 2>/dev/null | awk '/^Gradle / {print $2; exit}'
}

choose_gradle() {
  # Prefer an already bootstrapped local Gradle.
  if [ -x "$GRADLE_HOME_LOCAL/bin/gradle" ]; then
    printf '%s\n' "$GRADLE_HOME_LOCAL/bin/gradle"
    return 0
  fi

  # Reuse the same Gradle from an earlier Scarface Stego Studio Mobile build
  # in the Downloads directory, so version upgrades do not redownload ~130 MB.
  local sibling
  sibling="$(find "$(dirname "$HERE")" -maxdepth 3 -type f -path "*/.build-tools/gradle-$GRADLE_VERSION/bin/gradle" -perm -u+x 2>/dev/null | head -n1 || true)"
  if [ -n "$sibling" ]; then
    printf '%s\n' "$sibling"
    return 0
  fi

  # Use a compatible system Gradle if available.
  if command -v gradle >/dev/null 2>&1; then
    local gv
    gv="$(gradle_version_of "$(command -v gradle)" || true)"
    if [ -n "$gv" ] && version_ge "$gv" "$GRADLE_VERSION"; then
      printf '%s\n' "$(command -v gradle)"
      return 0
    fi
  fi

  mkdir -p "$TOOLS_DIR"
  local zip="$TOOLS_DIR/gradle-$GRADLE_VERSION-bin.zip"
  local url="https://services.gradle.org/distributions/gradle-$GRADLE_VERSION-bin.zip"

  echo "System Gradle is missing or too old; bootstrapping Gradle $GRADLE_VERSION locally..." >&2
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 -o "$zip" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$zip" "$url"
  else
    cat >&2 <<'MSG'
Neither curl nor wget is installed. Install one and retry:
  sudo apt install curl
MSG
    exit 3
  fi

  if ! command -v unzip >/dev/null 2>&1; then
    cat >&2 <<'MSG'
unzip is required. Install it and retry:
  sudo apt install unzip
MSG
    exit 3
  fi

  rm -rf "$GRADLE_HOME_LOCAL"
  unzip -q "$zip" -d "$TOOLS_DIR"
  rm -f "$zip"
  printf '%s\n' "$GRADLE_HOME_LOCAL/bin/gradle"
}


find_android_sdk() {
  local candidates=()

  [ -n "${ANDROID_HOME:-}" ] && candidates+=("$ANDROID_HOME")
  [ -n "${ANDROID_SDK_ROOT:-}" ] && candidates+=("$ANDROID_SDK_ROOT")

  candidates+=(
    "$HOME/Android/Sdk"
    "$HOME/Android/sdk"
    "$HOME/android-sdk"
    "/opt/android-sdk"
    "/usr/lib/android-sdk"
    "/usr/local/lib/android-sdk"
  )

  # If adb or sdkmanager is already on PATH, resolve it and infer the SDK root.
  local tool resolved inferred
  for tool in adb sdkmanager; do
    if command -v "$tool" >/dev/null 2>&1; then
      resolved="$(readlink -f "$(command -v "$tool")" 2>/dev/null || command -v "$tool")"
      case "$resolved" in
        */platform-tools/adb)
          inferred="${resolved%/platform-tools/adb}"
          candidates+=("$inferred")
          ;;
        */cmdline-tools/*/bin/sdkmanager)
          inferred="${resolved%%/cmdline-tools/*}"
          candidates+=("$inferred")
          ;;
        */tools/bin/sdkmanager)
          inferred="${resolved%/tools/bin/sdkmanager}"
          candidates+=("$inferred")
          ;;
      esac
    fi
  done

  local sdk
  for sdk in "${candidates[@]}"; do
    [ -n "$sdk" ] || continue
    if [ -d "$sdk" ] && { [ -d "$sdk/platforms" ] || [ -d "$sdk/platform-tools" ] || [ -d "$sdk/cmdline-tools" ]; }; then
      printf '%s\n' "$sdk"
      return 0
    fi
  done
  return 1
}

configure_android_sdk() {
  local sdk
  if ! sdk="$(find_android_sdk)"; then
    cat >&2 <<'MSG'
Android SDK was not found.

If you already installed Android Studio/SDK, find the SDK folder and run:
  export ANDROID_HOME="$HOME/Android/Sdk"
  ./build.sh

Common Kali/Linux SDK locations are:
  $HOME/Android/Sdk
  $HOME/Android/sdk
  /usr/lib/android-sdk

You can also create local.properties manually with:
  sdk.dir=/absolute/path/to/your/Android/Sdk
MSG
    exit 4
  fi

  export ANDROID_HOME="$sdk"
  export ANDROID_SDK_ROOT="$sdk"
  printf 'sdk.dir=%s\n' "$sdk" > "$HERE/local.properties"
  echo "Using Android SDK: $sdk"

  if [ ! -d "$sdk/platforms/android-36" ]; then
    echo "WARNING: Android platform 36 was not found at: $sdk/platforms/android-36" >&2
    echo "Install Android SDK Platform 36 with Android Studio or sdkmanager, then rerun ./build.sh." >&2
  fi
}

choose_java
configure_android_sdk
GRADLE_BIN="$(choose_gradle)"

echo "Using Java: $($JAVA_HOME/bin/java -version 2>&1 | head -n1)"
echo "Using Gradle: $($GRADLE_BIN --version | awk '/^Gradle / {print $2; exit}')"

echo "Building Scarface Stego Studio Mobile..."
"$GRADLE_BIN" :app:assembleDebug

echo
echo "Build complete. APK:"
echo "$HERE/app/build/outputs/apk/debug/app-debug.apk"
