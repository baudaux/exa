#!/bin/sh

../../../../emscripten/emcc src/login.c -o exa/login.js -I../../../packages/util-linux/include -sASYNCIFY -sTOTAL_MEMORY=64KB -sTOTAL_STACK=32kB
