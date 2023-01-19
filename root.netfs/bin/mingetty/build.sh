#!/bin/sh

../../../../emscripten/emcc src/mingetty.c -o exa/mingetty.js -sASYNCIFY -sTOTAL_MEMORY=64KB -sTOTAL_STACK=32kB
