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

#include <libminhook/export.h>

#if !defined(_M_IX86)  && !defined(_M_X64) && \
    !defined(__i386__) && !defined(__x86_64__)
#  error MinHook supports only x86 and x64 targets
#endif

#ifdef __cplusplus
extern "C"
{
#endif

/* Status that the library functions return.
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
  MH_ERROR_UNSUPPORTED_FUNCTION, /* Target's code can't be relocated. */
  MH_ERROR_MEMORY_ALLOC,         /* Unable to allocate memory. */
  MH_ERROR_MEMORY_PROTECT,       /* Unable to change memory protection. */
  MH_ERROR_MODULE_NOT_FOUND,     /* Module not loaded. */
  MH_ERROR_FUNCTION_NOT_FOUND    /* Function not exported by the module. */
};

/* Target that denotes all the hooks (see mh_enable_hook() and
 * mh_queue_enable_hook()).
 */
#define MH_ALL_HOOKS NULL

/* Note that the functions below may be called from any thread. They
 * serialize on an internal lock and, while patching code, suspend all the
 * other threads of the process. Those that need the library initialized
 * return MH_ERROR_NOT_INITIALIZED if it is not.
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
 * starting instructions can't be relocated into the trampoline, and
 * MH_ERROR_MEMORY_ALLOC if unable to allocate the trampoline or the hook.
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

/* The same as mh_create_hook_api_ex() with target being NULL.
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_create_hook_api (const wchar_t* module,
                    const char* function,
                    void* detour,
                    void** original);

/* Disable the hook of the target function if it is enabled and remove it.
 * Return MH_ERROR_NOT_CREATED if the target has no hook.
 *
 * If unable to disable the hook (see mh_disable_hook()), then return that
 * status and keep the hook enabled.
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_remove_hook (void* target);

/* Enable or disable the hook of the target function or, if target is
 * MH_ALL_HOOKS, all the hooks. Return MH_ERROR_NOT_CREATED if the target
 * has no hook and MH_ERROR_ENABLED or MH_ERROR_DISABLED if its hook is
 * already in that state.
 *
 * Return MH_ERROR_MEMORY_ALLOC if unable to enumerate the process's threads
 * and MH_ERROR_MEMORY_PROTECT if unable to make the target writable. For
 * MH_ALL_HOOKS the hooks before the one that fails stay changed.
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_enable_hook (void* target);

LIBMINHOOK_SYMEXPORT enum mh_status
mh_disable_hook (void* target);

/* Queue enabling or disabling the hook of the target function or, if
 * target is MH_ALL_HOOKS, all the hooks. Return MH_ERROR_NOT_CREATED if
 * the target has no hook.
 *
 * Note that queuing only records the state. See mh_apply_queued() for
 * applying it.
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

/* Return the status enumerator's name (for example, "MH_ERROR_ENABLED") or
 * "(unknown)" if the value is not an enumerator.
 */
LIBMINHOOK_SYMEXPORT const char*
mh_status_to_string (enum mh_status);

#ifdef __cplusplus
}
#endif
