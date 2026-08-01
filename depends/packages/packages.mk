packages:= openssl gmp

# Android takes OpenSSL 3.x instead: 1.1.1k cannot build against a modern NDK.
# See packages/openssl_android.mk.
ifeq ($(host_os),android)
packages:= openssl_android gmp
endif

boost_packages = boost

libevent_packages = libevent

qrencode_linux_packages = qrencode
qrencode_darwin_packages = qrencode
qrencode_mingw32_packages = qrencode

qt_linux_packages:=qt expat libxcb xcb_proto libXau xproto freetype fontconfig libxkbcommon libxcb_util libxcb_util_render libxcb_util_keysyms libxcb_util_image libxcb_util_wm
qt_darwin_packages=qt
qt_mingw32_packages=qt

bdb_packages=bdb
sqlite_packages=sqlite

zmq_packages=zeromq

multiprocess_packages = libmultiprocess capnp
multiprocess_native_packages = native_libmultiprocess native_capnp

usdt_linux_packages=systemtap

$(host_arch)_$(host_os)_native_packages += native_b2
