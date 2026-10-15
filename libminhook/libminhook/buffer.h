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

#include <stdbool.h>

/* Executable memory slots for the trampolines.
 *
 * On x64 we allocate each slot within 1 GiB of its origin (the target
 * function) so that the relative jumps between the two reach.
 */

/* Size of a slot.
 */
#if defined(_M_X64) || defined(__x86_64__)
#  define MH_MEMORY_SLOT_SIZE 64
#else
#  define MH_MEMORY_SLOT_SIZE 32
#endif

/* Size of a page, the unit of memory protection.
 */
#define MH_PAGE_SIZE 0x1000

/* Initialize the slot allocator. Call before allocating a slot.
 *
 * Note that the allocator keeps its blocks across initializations since
 * the slots of retired trampolines stay in use (see mh_remove_hook()).
 */
void
mh_initialize_buffer (void);

/* Return a slot near the origin or NULL if unable to allocate one.
 */
void*
mh_allocate_buffer (void* origin);

/* Return the slot to its block and release the block if it has no slots in
 * use.
 */
void
mh_free_buffer (void* buffer);

/* Return true if the address is in committed executable memory.
 */
bool
mh_executable_address (const void* address);
