# minhook - x86/x64 API hooking C library for Windows

This repository contains the `libminhook` C library, a maintained fork of
[MinHook](https://github.com/TsudaKageyu/minhook) 1.3.4, which hooks
functions in the current process on x86 and x64 Windows. The package
[`README.md`](libminhook/README.md) describes how it differs from MinHook.

This file contains setup instructions and other details that are more
appropriate for development rather than consumption. If you want to use
`libminhook` in your `build2`-based project, then instead see the
accompanying package [`README.md`](libminhook/README.md) file.

The development setup for `minhook` uses the standard `bdep`-based workflow.
The library only builds for Windows, so on Linux we cross-compile with
MinGW-w64 GCC and run the tests under Wine. For example:

```
git clone .../minhook.git
cd minhook

bdep init -C @mingw cc                                        \
  config.c=x86_64-w64-mingw32-gcc                             \
  config.cxx=x86_64-w64-mingw32-g++                           \
  config.test.runner="env WINEPATH=/usr/x86_64-w64-mingw32/sys-root/mingw/bin wine"

bdep update
bdep test
```
