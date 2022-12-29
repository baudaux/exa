#!/bin/sh

../../../../emscripten/emcc src/resmgr.c src/vfs.c src/device.c src/process.c -o exa/resmgr.js -I../include -sASYNCIFY -sTOTAL_MEMORY=512KB -sTOTAL_STACK=128kB
