# libminhook - x86/x64 API hooking C library for Windows

The `libminhook` C library hooks functions in the current process on
x86 and x64 Windows. It overwrites the first instructions of a target
function with a jump to a detour function and builds a trampoline that
calls the original target function. It requires Windows Vista or later.

The library is a maintained fork of
[MinHook](https://github.com/TsudaKageyu/minhook) 1.3.4 by Tsuda Kageyu. Its
interface follows MinHook's with lowercase names (`mh_create_hook()` for
`MH_CreateHook()`, `enum mh_status` for `MH_STATUS`, and so on) and a few
differences (see below).


## Usage

To start using `libminhook` in your project, add the following `depends`
value to your `manifest`, adjusting the version constraint as appropriate:

```
depends: libminhook ^0.1.0
```

Then import the library in your `buildfile`:

```
import libs = libminhook%lib{minhook}
```

And hook a function:

```
#include <libminhook/minhook.h>

static int (*original) (int);

static int
detour (int x)
{
  return original (x) + 1;
}

...

mh_initialize ();
mh_create_hook ((void*) &target, (void*) &detour, (void**) &original);
mh_enable_hook ((void*) &target);
```

See `libminhook/minhook.h` for the complete interface.


## Differences from MinHook

Trampolines and hooks:

* `mh_remove_hook()` retires the hook's trampoline and keeps it allocated,
  since a thread may still enter it (for example, by returning from a call
  that the trampoline made). Its second argument receives the trampoline's
  identifier, which `mh_reclaim()` takes to free it once no thread can enter
  it. `mh_reclaim()` returns `MH_ERROR_BUSY` if a thread is executing the
  trampoline and `MH_ERROR_NOT_RETIRED` for an unknown identifier.

* `mh_uninitialize()` keeps the trampolines of the remaining hooks allocated
  for the same reason.

* `mh_create_hook()` returns `MH_ERROR_OVERLAPPING` if the code that the
  hook overwrites or relocates overlaps that of another hook.

Relocation:

* Instructions are decoded with [Zydis](https://zydis.re/) in place of the
  Hacker Disassembler Engine.

* `mh_create_hook()` returns `MH_ERROR_UNSUPPORTED_FUNCTION` for code that
  the trampoline cannot reproduce: relative branches with the 16-bit operand
  size, EIP-relative addressing, relative instructions such as `xbegin`,
  RIP-relative displacements that no longer fit into 32 bits, and branches
  within the relocated code whose distance would change or whose destination
  is in the middle of an instruction.

Memory and threads:

* The code of the target and the padding around it are only read within
  executable memory.

* The protection of each page that a hook's jump spans is changed and
  restored separately.

* The suspended threads are only moved once a patch succeeds. Disabling a
  hook moves a thread that is suspended on its long jump in the hot patch
  area back to the target.

* The threads are enumerated with `NtGetNextThread()`, which requires
  Windows Vista or later.
