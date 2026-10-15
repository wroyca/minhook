#pragma once

#if defined(LIBMINHOOK_STATIC)         /* Using static. */
#  define LIBMINHOOK_SYMEXPORT
#elif defined(LIBMINHOOK_STATIC_BUILD) /* Building static. */
#  define LIBMINHOOK_SYMEXPORT
#elif defined(LIBMINHOOK_SHARED)       /* Using shared. */
#  ifdef _WIN32
#    define LIBMINHOOK_SYMEXPORT __declspec(dllimport)
#  else
#    define LIBMINHOOK_SYMEXPORT
#  endif
#elif defined(LIBMINHOOK_SHARED_BUILD) /* Building shared. */
#  ifdef _WIN32
#    define LIBMINHOOK_SYMEXPORT __declspec(dllexport)
#  else
#    define LIBMINHOOK_SYMEXPORT
#  endif
#else
/* If none of the above macros are defined, then we assume we are being used
 * by some third-party build system that doesn't signal the library type.
 * This fallback works for both static and shared libraries since we only
 * export functions. For the shared case the calls go through the import
 * thunks, which is a bit slower than with dllimport.
 */
#  define LIBMINHOOK_SYMEXPORT         /* Using static or shared. */
#endif
