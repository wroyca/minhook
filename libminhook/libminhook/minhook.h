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

/* Status of a MinHook function call.
 */
enum mh_status
{
  MH_UNKNOWN = -1, /* Never returned. */
  MH_OK = 0,

  MH_ERROR_ALREADY_INITIALIZED,  /* Already initialized. */
  MH_ERROR_NOT_INITIALIZED,      /* Not yet or no longer initialized. */
  MH_ERROR_ALREADY_CREATED,      /* Target hook already created. */
  MH_ERROR_NOT_CREATED,          /* Target hook not created. */
  MH_ERROR_ENABLED,              /* Target hook already enabled. */
  MH_ERROR_DISABLED,             /* Target hook not enabled. */
  MH_ERROR_NOT_EXECUTABLE,       /* Address not in committed code. */
  MH_ERROR_UNSUPPORTED_FUNCTION, /* Target function cannot be hooked. */
  MH_ERROR_MEMORY_ALLOC,         /* Unable to allocate memory. */
  MH_ERROR_MEMORY_PROTECT,       /* Unable to change memory protection. */
  MH_ERROR_MODULE_NOT_FOUND,     /* Module not loaded. */
  MH_ERROR_FUNCTION_NOT_FOUND    /* Function not exported by module. */
};

/* Target that denotes all the created hooks (see mh_enable_hook(),
 * mh_disable_hook(), mh_queue_enable_hook(), and mh_queue_disable_hook()).
 */
#define MH_ALL_HOOKS NULL

/* Initialize the library. Call exactly once before any other function.
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_initialize (void);

/* Disable all the hooks and uninitialize the library. Call exactly once
 * after all the other functions.
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_uninitialize (void);

/* Create a disabled hook that redirects the target function to the detour
 * function. If original is not NULL, then store in it the trampoline that
 * calls the original target function.
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_create_hook (void* target, void* detour, void** original);

/* Create a disabled hook for the function exported under the specified
 * name by the specified loaded module. If target is not NULL, then store
 * the function's address in it. Otherwise, the same as mh_create_hook().
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_create_hook_api_ex (const wchar_t* module,
                       const char* function,
                       void* detour,
                       void** original,
                       void** target);

/* The same as mh_create_hook_api_ex() without the target.
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_create_hook_api (const wchar_t* module,
                    const char* function,
                    void* detour,
                    void** original);

/* Disable, if enabled, and remove the hook of the target function.
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_remove_hook (void* target);

/* Enable or disable the hook of the target function or, if the target is
 * MH_ALL_HOOKS, all the hooks at once.
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_enable_hook (void* target);

LIBMINHOOK_SYMEXPORT enum mh_status
mh_disable_hook (void* target);

/* Queue enabling or disabling the hook of the target function or, if the
 * target is MH_ALL_HOOKS, all the hooks (see mh_apply_queued()).
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_queue_enable_hook (void* target);

LIBMINHOOK_SYMEXPORT enum mh_status
mh_queue_disable_hook (void* target);

/* Apply all the queued changes at once.
 */
LIBMINHOOK_SYMEXPORT enum mh_status
mh_apply_queued (void);

/* Return the status enumerator name, for example, "MH_ERROR_ENABLED".
 */
LIBMINHOOK_SYMEXPORT const char*
mh_status_to_string (enum mh_status);

#ifdef __cplusplus
}
#endif
