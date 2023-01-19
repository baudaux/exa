#!/bin/sh

../../../../emscripten/emcc src/agetty.c ../../../packages/util-linux/lib/color-names.c ../../../packages/util-linux/lib/ttyutils.c ../../../packages/util-linux/lib/logindefs.c ../../../packages/util-linux/lib/strutils.c -o exa/agetty.js -D_PATH_RUNSTATEDIR="" -D_PATH_SYSCONFSTATICDIR="" -I../../../packages/util-linux/include -sASYNCIFY -sTOTAL_MEMORY=128KB -sTOTAL_STACK=64kB
