#!/bin/sh

../../../../emscripten/emcc src/tty.c -o exa/tty.js -I../include -sASYNCIFY -sTOTAL_MEMORY=64KB -sTOTAL_STACK=32kB -sASYNCIFY_IMPORTS=[probe_terminal]
