#!/bin/sh
# Isolate Gradle, Android preferences and generated debug signing material.
set -eu
tool=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$tool/.gradle-home/home" "$tool/.gradle-home/android-user"
if [ ! -f "$tool/.gradle-home/debug.keystore" ]; then
    keytool_bin=$(command -v keytool)
    env HOME="$tool/.gradle-home/home" "$keytool_bin" -J-Duser.home="$tool/.gradle-home/home" -genkeypair -keystore "$tool/.gradle-home/debug.keystore" -storepass android -keypass android -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 3650 -dname 'CN=Android Debug,O=Android,C=US' >/dev/null 2>&1
fi
exec env HOME="$tool/.gradle-home/home" ANDROID_USER_HOME="$tool/.gradle-home/android-user" GRADLE_USER_HOME="$tool/.gradle-home" "$tool/gradlew" --project-dir "$tool" -Duser.home="$tool/.gradle-home/home" --no-daemon --max-workers=2 "$@"
