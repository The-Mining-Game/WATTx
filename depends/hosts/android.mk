# Android (NDK) host support.
#
# Builds the daemon's dependencies for Android so the core can run on a phone —
# the wallet app currently mines through a pool because there is no consensus
# code on the device.
#
# Requires ANDROID_NDK to point at an NDK r23+ install, e.g.
#   make -C depends HOST=aarch64-linux-android ANDROID_NDK=$HOME/Android/Sdk/ndk/25.1.8937393
#
# ANDROID_API_LEVEL 24 is the floor: earlier levels lack the 64-bit file API and
# the atomics the C++ runtime expects. Qt is not built here — a phone runs the
# headless daemon, and the UI stays Flutter.
ANDROID_API_LEVEL ?= 24
ANDROID_TOOLCHAIN_BIN = $(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin

# OpenSSL 1.1.1k's android target validates the NDK by looking for the legacy
# platforms/ directory, which NDK r23 removed. Point that one package at an
# older NDK if you have one (ANDROID_NDK_OPENSSL); everything else uses the
# modern NDK above.
ANDROID_NDK_OPENSSL ?= $(ANDROID_NDK)

android_CC = $(ANDROID_TOOLCHAIN_BIN)/$(host_arch)-linux-android$(if $(findstring arm,$(host_arch)),eabi,)$(ANDROID_API_LEVEL)-clang
android_CXX = $(ANDROID_TOOLCHAIN_BIN)/$(host_arch)-linux-android$(if $(findstring arm,$(host_arch)),eabi,)$(ANDROID_API_LEVEL)-clang++
android_AR = $(ANDROID_TOOLCHAIN_BIN)/llvm-ar
android_RANLIB = $(ANDROID_TOOLCHAIN_BIN)/llvm-ranlib
android_NM = $(ANDROID_TOOLCHAIN_BIN)/llvm-nm
android_STRIP = $(ANDROID_TOOLCHAIN_BIN)/llvm-strip
android_OBJDUMP = $(ANDROID_TOOLCHAIN_BIN)/llvm-objdump
android_OBJCOPY = $(ANDROID_TOOLCHAIN_BIN)/llvm-objcopy

# -fPIC everywhere: everything on Android is loaded as a shared object.
android_CFLAGS = -pipe -std=$(C_STANDARD) -fPIC
android_CXXFLAGS = -pipe -std=$(CXX_STANDARD) -fPIC
android_LDFLAGS = -static-libstdc++

android_release_CFLAGS = -O2
android_release_CXXFLAGS = $(android_release_CFLAGS)

android_debug_CFLAGS = -O1 -g
android_debug_CXXFLAGS = $(android_debug_CFLAGS)

android_debug_CPPFLAGS = -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC

android_cmake_system_name = Android
android_cmake_system_version = $(ANDROID_API_LEVEL)
