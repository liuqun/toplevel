#!/bin/bash

PREFIX=/usr/local
build_dir=openssl

if [ ! -d "$build_dir" ] ; then
  ./download_openssl.bash
fi

if [ -d "$build_dir" ] ; then
  cd $build_dir
  ./config enable-sm2 enable-sm3 enable-sm4 --prefix="$PREFIX" \
    && make \
    && echo "Build OK! type: sudo make -C openssl install"
fi
