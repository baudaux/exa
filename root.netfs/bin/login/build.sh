#!/bin/sh

../../../../emscripten/emcc src/login.c ../../../packages/util-linux/lib/logindefs.c ../../../packages/util-linux/lib/ttyutils.c ../../../packages/util-linux/lib/fileutils.c -o exa/login.js -I../../../packages/util-linux/include -I../../../packages/linux-pam/libpam/include -I../../../packages/linux-pam/libpam_misc/include -I../../../packages/linux-pam/libpamc/include -sASYNCIFY -sTOTAL_MEMORY=64KB -sTOTAL_STACK=32kB
