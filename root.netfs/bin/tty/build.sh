#!/bin/sh

../../../../emscripten/emcc src/tty.c -o exa/tty.js -I../include -sASYNCIFY -sTOTAL_MEMORY=128KB -sTOTAL_STACK=64kB
