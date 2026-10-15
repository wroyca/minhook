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
 * by some third-party build system that cannot/doesn't signal the library
 * type. Note that this fallback works for both static and shared libraries
 * provided the library only exports functions (in other words, no global
 * exported data) and for the shared case the result will be sub-optimal
 * compared to having dllimport. If, however, your library does export data,
 * then you will probably want to replace the fallback with the (commented
 * out) error since it won't work for the shared case.
 */
#  define LIBMINHOOK_SYMEXPORT         /* Using static or shared. */
/*#  error define LIBMINHOOK_STATIC or LIBMINHOOK_SHARED preprocessor macro to signal libminhook library type being linked */
#endif
