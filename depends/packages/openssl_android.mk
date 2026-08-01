package=openssl_android
$(package)_version=3.0.21
$(package)_download_path=https://github.com/openssl/openssl/releases/download/openssl-$($(package)_version)
$(package)_file_name=openssl-$($(package)_version).tar.gz
$(package)_sha256_hash=617e29af8e421f46649484a4937e48c685e47f46488167c982f88bc4ec1d522f

# OpenSSL for the Android host.
#
# 1.1.1k cannot build against a modern NDK: its generated Makefile emits
# -gcc-toolchain $(ANDROID_NDK_HOME)/... which is empty at build time (leaving
# paths like /toolchains/... and /sysroot/...), and current clang rejects the
# flag outright. 3.x targets the unified NDK toolchain directly and needs none
# of that. The daemon only uses the modern EVP interface, so the version
# difference is invisible to the source.
#
# Kept separate from openssl.mk so Linux and Windows releases stay on the
# version they have shipped with; only Android moves.

define $(package)_set_vars
$(package)_config_opts=--prefix=$(host_prefix) --openssldir=$(host_prefix)/etc/openssl
$(package)_config_opts+=android-arm64
$(package)_config_opts+=no-shared no-tests no-comp no-legacy
$(package)_config_opts+=no-ssl3 no-weak-ssl-ciphers
$(package)_config_opts+=-D__ANDROID_API__=$(ANDROID_API_LEVEL)
$(package)_config_opts+=-fPIC
endef

# depends appends its own PATH after any per-package config_env, so the NDK bin
# is prepended on the command line where nothing can clobber it. ANDROID_NDK_ROOT
# is what 3.x reads, and it must stay set for the build step too, not just
# configure.
$(package)_ndk_bin=$(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin
$(package)_ndk_env=ANDROID_NDK_ROOT="$(ANDROID_NDK)" PATH="$($(package)_ndk_bin):/usr/local/bin:/usr/bin:/bin"

define $(package)_config_cmds
  $($(package)_ndk_env) ./Configure $($(package)_config_opts)
endef

define $(package)_build_cmds
  $($(package)_ndk_env) $(MAKE) -j1 build_libs
endef

define $(package)_stage_cmds
  $($(package)_ndk_env) $(MAKE) DESTDIR=$($(package)_staging_dir) -j1 install_dev
endef

define $(package)_postprocess_cmds
  rm -rf share bin etc
endef
