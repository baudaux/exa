#!/bin/sh

../../../../emscripten/emcc src/netfs.c -o exa/netfs.js -I../include -sASYNCIFY -sTOTAL_MEMORY=64KB -sTOTAL_STACK=32kB
