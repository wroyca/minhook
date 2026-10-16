/*
 *  MinHook - The Minimalistic API Hooking Library for x64/x86
 *  Copyright (C) 2009-2017 Tsuda Kageyu.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
 *  OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#include <stddef.h> /* NULL, wchar_t */
#include <stdint.h> /* uint64_t */

#include <libminhook/export.h>

#if !defined(_M_IX86)  && !defined(_M_X64) && \
    !defined(__i386__) && !defined(__x86_64__)
#  error MinHook supports only x86 and x64 targets
#endif

#ifdef __cplusplus
extern "C"
{
#endif

/* Library function status.
 */
enum mh_status
{
  MH_UNKNOWN = -1, /* Never returned. */
  MH_OK = 0,

  MH_ERROR_ALREADY_INITIALIZED,  /* Library already initialized. */
  MH_ERROR_NOT_INITIALIZED,      /* Library not initialized. */
  MH_ERROR_ALREADY_CREATED,      /* Hook for the target already created. */
  MH_ERROR_NOT_CREATED,          /* No hook for the target. */
  MH_ERROR_ENABLED,              /* Hook already enabled. */
  MH_ERROR_DISABLED,             /* Hook already disabled. */
  MH_ERROR_NOT_EXECUTABLE,       /* Address outside executable memory. */
  MH_ERROR_UNSUPPORTED_FUNCTION, /* Target's code not relocatable. */
  MH_ERROR_MEMORY_ALLOC,         /* Unable to allocate memory. */
  MH_ERROR_MEMORY_PROTECT,       /* Unable to change memory protection. */
  MH_ERROR_MODULE_NOT_FOUND,     /* Module not loaded. */
  MH_ERROR_FUNCTION_NOT_FOUND,   /* Function not exported by the module. */
  MH_ERROR_BUSY,                 /* Trampoline executed by a thread. */
  MH_ERROR_NOT_RETIRED,          /* No retired trampoline with the id. */
  MH_ERROR_OVERLAPPING           /* Overlap with another hook's code. */
};

/* Retired trampoline identifier (see mh_remove_hook()). The library never
 * issues 0 or the same identifier twice.
 */
typedef uint64_t mh_retirement_id;

/* Special target that denotes all the hooks (see mh_enable_hook() and
 * mh_queue_enable_hook()).
 */
#define MH_ALL_HOOKS NULL

/* Note that the functions below may be called from any thread. They
 * serialize on an internal lock and, while patching code, suspend all the
 * other threads of the process. Those that need the library initialized
 * return MH_ERROR_NOT_INITIALIZED if it is not.
 *
 * Note also that the library never frees a trampoline on its own since it
 * cannot tell whether some thread may still enter it. See mh_remove_hook()
 * and mh_reclaim_trampoline() for details.
 */

/* Initialize the library. Return MH_ERROR_ALREADY_INITIALIZED if it is
 * already initialized and MH_ERROR_MEMORY_ALLOC if unable to create the
 * library's heap.
 *
 * Note that the library can be initialized again after mh_uninitialize().
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_initialize (void);

/* Disable and remove all the hooks and uninitialize the library.
 *
 * If unable to disable the hooks (see mh_disable_hook()), then return that
 * status and leave the library initialized.
 *
 * Note that the trampolines of the hooks stay allocated until the process
 * terminates. To be able to reclaim a trampoline, remove its hook with
 * mh_remove_hook() first.
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_uninitialize (void);

/* Create a disabled hook that redirects the target function to the detour
 * function. If original is not NULL, then store in it the trampoline that
 * calls the original target function.
 *
 * Return MH_ERROR_NOT_EXECUTABLE if the target or the detour is outside
 * committed executable memory, MH_ERROR_ALREADY_CREATED if the target
 * already has a hook, MH_ERROR_UNSUPPORTED_FUNCTION if the target's
 * starting instructions cannot be relocated into the trampoline,
 * MH_ERROR_OVERLAPPING if the code that the hook overwrites or relocates
 * overlaps that of another hook, and MH_ERROR_MEMORY_ALLOC if unable to
 * allocate the trampoline or the hook.
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_create_hook (void* target, void* detour, void** original);

/* Create a disabled hook for the function that the loaded module exports
 * under the name. If target is not NULL, then store the function's address
 * in it, even if creating the hook fails.
 *
 * Return MH_ERROR_MODULE_NOT_FOUND if the module is not loaded (we don't
 * load it) and MH_ERROR_FUNCTION_NOT_FOUND if it doesn't export the
 * function. Otherwise, the same as mh_create_hook().
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_create_hook_api_ex (const wchar_t* module,
                       const char* function,
                       void* detour,
                       void** original,
                       void** target);

/* As above but without returning the function's address.
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_create_hook_api (const wchar_t* module,
                    const char* function,
                    void* detour,
                    void** original);

/* Disable the hook of the target function if it is enabled, remove it, and
 * retire its trampoline. If retired is not NULL, then store in it the
 * trampoline's retirement id. Return MH_ERROR_NOT_CREATED if the target has
 * no hook and MH_ERROR_MEMORY_ALLOC if unable to record the retirement.
 *
 * If unable to disable the hook (see mh_disable_hook()), then return that
 * status and keep the hook enabled.
 *
 * A retired trampoline stays allocated and executable since a thread may
 * still enter it, for example, through the trampoline pointer that
 * mh_create_hook() stored or by returning from a call that the trampoline
 * made. It is the caller's responsibility to establish that no thread can
 * enter it any longer and to then free it with mh_reclaim_trampoline(). If
 * retired is NULL, then the trampoline stays allocated until the process
 * terminates.
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_remove_hook (void* target, mh_retirement_id* retired);

/* Free the retired trampoline with the id. The caller must make sure that
 * no thread can enter it (see mh_remove_hook()). Return
 * MH_ERROR_NOT_RETIRED if no trampoline with the id is retired.
 *
 * Before freeing the trampoline, suspend the process's other threads and
 * check where they are. If a thread is executing the trampoline or if we
 * cannot suspend a thread or read where it is, then return MH_ERROR_BUSY
 * and leave the trampoline retired. Return MH_ERROR_MEMORY_ALLOC if unable
 * to enumerate the threads, which also leaves it retired.
 *
 * Note that this check doesn't establish that no thread can enter the
 * trampoline. For example, a thread that is about to call it through a
 * saved pointer is not executing it yet.
 *
 * Note also that this function works while the library is not initialized.
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_reclaim_trampoline (mh_retirement_id);

/* Enable or disable the hook of the target function or, if target is
 * MH_ALL_HOOKS, all the hooks. Return MH_ERROR_NOT_CREATED if the target
 * has no hook and MH_ERROR_ENABLED or MH_ERROR_DISABLED if its hook is
 * already in that state.
 *
 * Return MH_ERROR_MEMORY_ALLOC if unable to enumerate the process's threads
 * and MH_ERROR_MEMORY_PROTECT if unable to make the target writable. If
 * target is MH_ALL_HOOKS, then the hooks before the one that fails keep
 * their new state.
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_enable_hook (void* target);

LIBMINHOOK_SYMEXPORT enum mh_status
mh_disable_hook (void* target);

/* Queue enabling or disabling the hook of the target function or, if
 * target is MH_ALL_HOOKS, all the hooks. Return MH_ERROR_NOT_CREATED if
 * the target has no hook.
 *
 * Note that this function only records the state, which mh_apply_queued()
 * then applies.
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_queue_enable_hook (void* target);

LIBMINHOOK_SYMEXPORT enum mh_status
mh_queue_disable_hook (void* target);

/* Bring every hook into its queued state, suspending the process's other
 * threads once for all of them. Return the same errors as mh_enable_hook()
 * with MH_ALL_HOOKS.
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_apply_queued (void);

/* Return the status enumerator's name (e.g., "MH_ERROR_ENABLED") or
 * "(unknown)" if the value is not an enumerator.
 */
LIBMINHOOK_SYMEXPORT const char*
mh_status_to_string (enum mh_status);

#ifdef __cplusplus
}
#endif
