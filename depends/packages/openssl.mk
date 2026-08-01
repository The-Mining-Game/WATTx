package=openssl
$(package)_version=1.1.1k
$(package)_download_path=https://www.openssl.org/source
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=892a0875b9872acd04a9fde79b1f943075d5ea162415de3047c327df33fbaee5

define $(package)_set_vars
$(package)_config_env=AR="$($(package)_ar)" RANLIB="$($(package)_ranlib)" CC="$($(package)_cc)"
# OpenSSL's android-* targets look the NDK up themselves and expect its clang
# on PATH, so hand them both rather than only CC.
# Per OpenSSL's own NOTES.ANDROID: CC must be the bare name "clang" with the
# NDK toolchain on PATH. Handing it the absolute clang path makes Configure
# fall through to the pre-r18 gcc naming and hunt for aarch64-linux-android-gcc,
# which no modern NDK ships.
# Configure insists the clang it finds on PATH lives under the NDK it just
# validated, so this package uses one NDK end to end (the legacy one, which
# still has the platforms/ directory 1.1.1k checks for). The rest of the build
# uses the modern NDK; the two produce link-compatible arm64 objects.
$(package)_config_env_android=CC=clang AR="$(ANDROID_NDK_OPENSSL)/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar" RANLIB="$(ANDROID_NDK_OPENSSL)/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ranlib" ANDROID_NDK_HOME="$(ANDROID_NDK_OPENSSL)" ANDROID_NDK_ROOT="$(ANDROID_NDK_OPENSSL)" PATH="$(ANDROID_NDK_OPENSSL)/toolchains/llvm/prebuilt/linux-x86_64/bin:$(PATH)"
$(package)_config_opts=--prefix=$(host_prefix) --openssldir=$(host_prefix)/etc/openssl
$(package)_config_opts+=no-camellia
$(package)_config_opts+=no-capieng
$(package)_config_opts+=no-cast
$(package)_config_opts+=no-comp
$(package)_config_opts+=no-dso
$(package)_config_opts+=no-dtls1
$(package)_config_opts+=no-ec_nistp_64_gcc_128
$(package)_config_opts+=no-gost
$(package)_config_opts+=no-heartbeats
$(package)_config_opts+=no-idea
$(package)_config_opts+=no-md2
$(package)_config_opts+=no-mdc2
$(package)_config_opts+=no-rc4
$(package)_config_opts+=no-rc5
$(package)_config_opts+=no-rdrand
$(package)_config_opts+=no-rfc3779
$(package)_config_opts+=no-sctp
$(package)_config_opts+=no-seed
$(package)_config_opts+=no-shared
$(package)_config_opts+=no-ssl-trace
$(package)_config_opts+=no-ssl2
$(package)_config_opts+=no-ssl3
$(package)_config_opts+=no-unit-test
$(package)_config_opts+=no-weak-ssl-ciphers
$(package)_config_opts+=no-whirlpool
$(package)_config_opts+=no-zlib
$(package)_config_opts+=no-zlib-dynamic
$(package)_config_opts+=no-sock
$(package)_config_opts+=-pipe -O2 $($(package)_cppflags)
$(package)_config_opts_linux=-fPIC -Wa,--noexecstack
# Android: without a target here Configure is handed an empty platform string
# and prints its full target list before failing. OpenSSL names the arm64 ABI
# android-arm64, and its Configure resolves the NDK through ANDROID_NDK_ROOT.
$(package)_config_opts_android=-fPIC -Wa,--noexecstack -D__ANDROID_API__=$(ANDROID_API_LEVEL)
$(package)_config_opts_aarch64_android=android-arm64
$(package)_config_opts_arm_android=android-arm
$(package)_config_opts_x86_64_android=android-x86_64
$(package)_config_opts_x86_64_linux=linux-x86_64
$(package)_config_opts_i686_linux=linux-generic32
$(package)_config_opts_arm_linux=linux-generic32
$(package)_config_opts_armv7l_linux=linux-generic32
$(package)_config_opts_aarch64_linux=linux-generic64
$(package)_config_opts_mipsel_linux=linux-generic32
$(package)_config_opts_mips_linux=linux-generic32
$(package)_config_opts_powerpc64_linux=linux-generic64
$(package)_config_opts_powerpc64le_linux=linux-generic64
$(package)_config_opts_riscv32_linux=linux-generic32
$(package)_config_opts_riscv64_linux=linux-generic64
$(package)_config_opts_x86_64_darwin=darwin64-x86_64-cc
$(package)_config_opts_aarch64_darwin += darwin64-arm64-cc
$(package)_config_opts_x86_64_mingw32=mingw64
$(package)_config_opts_i686_mingw32=mingw
endef

define $(package)_preprocess_cmds
  sed -i.old "s/built on: \$date/built on: date not available/g" util/mkbuildinf.pl && \
  sed -i.old "s|\"engines\", \"apps\", \"test\", \"util\", \"tools\", \"fuzz\"|\"engines\", \"util\", \"tools\"|" Configure
endef

# depends appends its own PATH after the per-package config_env, so exporting
# the NDK bin there gets overridden before Configure runs. Prepend it on the
# command itself, where nothing can clobber it.
ifeq ($(host_os),android)
$(package)_configure_path=PATH="$(ANDROID_NDK_OPENSSL)/toolchains/llvm/prebuilt/linux-x86_64/bin:/usr/local/bin:/usr/bin:/bin"
endif

define $(package)_config_cmds
  $($(package)_configure_path) ./Configure $($(package)_config_opts)
endef

define $(package)_build_cmds
  $(MAKE) -j1 build_libs libcrypto.pc libssl.pc openssl.pc
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) -j1 install_sw
endef

define $(package)_postprocess_cmds
  rm -rf share bin etc
endef
