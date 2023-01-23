#!/bin/sh

../../../../emscripten/emcc src/login.c -o exa/login.js -sASYNCIFY -sTOTAL_MEMORY=64KB -sTOTAL_STACK=32kB
