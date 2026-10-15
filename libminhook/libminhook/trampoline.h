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

#include <stdint.h>
#include <stdbool.h>

/* Encodings of the x86 and x64 branch instructions that the trampolines
 * and the hooks are made of.
 */
#pragma pack(push, 1)

/* EB xx: jmp +2+xx
 */
struct mh_jmp_rel_short
{
  uint8_t opcode;
  uint8_t operand;
};

/* E9 xxxxxxxx: jmp +5+xxxxxxxx
 * E8 xxxxxxxx: call +5+xxxxxxxx
 */
struct mh_jmp_rel
{
  uint8_t  opcode;
  uint32_t operand; /* Relative destination address. */
};

/* FF25 00000000: jmp [+6]
 */
struct mh_jmp_abs
{
  uint8_t  opcode0;
  uint8_t  opcode1;
  uint32_t dummy;
  uint64_t address; /* Absolute destination address. */
};

/* FF15 00000002: call [+6]
 * EB 08:         jmp +10
 */
struct mh_call_abs
{
  uint8_t  opcode0;
  uint8_t  opcode1;
  uint32_t dummy0;
  uint8_t  dummy1;
  uint8_t  dummy2;
  uint64_t address; /* Absolute destination address. */
};

/* 0F8* xxxxxxxx: j* +6+xxxxxxxx
 */
struct mh_jcc_rel
{
  uint8_t  opcode0;
  uint8_t  opcode1;
  uint32_t operand; /* Relative destination address. */
};

/* 7* 0E:         j* +16
 * FF25 00000000: jmp [+6]
 *
 * An absolute conditional jump, which x64 lacks.
 */
struct mh_jcc_abs
{
  uint8_t  opcode;
  uint8_t  dummy0;
  uint8_t  dummy1;
  uint8_t  dummy2;
  uint32_t dummy3;
  uint64_t address; /* Absolute destination address. */
};

#pragma pack(pop)

/* Trampoline description.
 *
 * The trampoline executes the target function's instructions that the hook
 * overwrites and jumps to the rest of the target function. The instruction
 * boundaries map the instructions between the two functions so that the
 * threads suspended within them can be moved.
 */
struct mh_trampoline
{
  void* target;     /* [in] Target function. */
  void* detour;     /* [in] Detour function. */
  void* trampoline; /* [in] Buffer for the trampoline and the relay. */

#if defined(_M_X64) || defined(__x86_64__)
  void* relay;      /* [out] Relay function that jumps to the detour. */
#endif

  bool    patch_above; /* [out] Patch the hot patch area. */
  uint8_t ip_count;    /* [out] Number of instruction boundaries. */
  uint8_t old_ips[8];  /* [out] Boundaries in the target function. */
  uint8_t new_ips[8];  /* [out] Boundaries in the trampoline. */
};

/* Build the trampoline for the target function. Return false if the
 * function cannot be hooked.
 */
bool
mh_create_trampoline (struct mh_trampoline*);
