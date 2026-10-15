# libminhook - x86/x64 API hooking C library for Windows

The `libminhook` C library hooks functions in the current process on
x86 and x64 Windows. It overwrites the first instructions of a target
function with a jump to a detour function and builds a trampoline that
calls the original target function.

The library is derived from [MinHook](https://github.com/TsudaKageyu/minhook)
1.3.4 by Tsuda Kageyu. Its interface follows MinHook's with lowercase names
(`mh_create_hook()` for `MH_CreateHook()`, `enum mh_status` for
`MH_STATUS`, and so on).


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
