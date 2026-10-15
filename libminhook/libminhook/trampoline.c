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

#include <libminhook/trampoline.h>

#include <assert.h>
#include <string.h> /* memcpy() */

#include <libminhook/buffer.h>

#if defined(_M_X64) || defined(__x86_64__)
#  include <libminhook/hde64.h>

typedef struct hde64_instruction instruction;

#  define INSTRUCTION_ERROR HDE64_F_ERROR

static inline unsigned int
decode (const void* code, instruction* i)
{
  return hde64_disasm (code, i);
}

/* Maximum size of the trampoline. The relay follows it in the same slot.
 */
#  define TRAMPOLINE_MAX_SIZE                                                \
  (MH_MEMORY_SLOT_SIZE - sizeof (struct mh_jmp_abs))
#else
#  include <libminhook/hde32.h>

typedef struct hde32_instruction instruction;

#  define INSTRUCTION_ERROR HDE32_F_ERROR

static inline unsigned int
decode (const void* code, instruction* i)
{
  return hde32_disasm (code, i);
}

#  define TRAMPOLINE_MAX_SIZE MH_MEMORY_SLOT_SIZE
#endif

/* Sign-extend the 8-bit or 32-bit relative operand to an address offset.
 */
static inline uintptr_t
offset8 (uint8_t v)
{
  return (uintptr_t) (intptr_t) (int8_t) v;
}

static inline uintptr_t
offset32 (uint32_t v)
{
  return (uintptr_t) (intptr_t) (int32_t) v;
}

/* Trampoline builder state.
 */
struct builder
{
  struct mh_trampoline* trampoline;

  uint8_t   old_pos;  /* Current instruction offset in the target. */
  uint8_t   new_pos;  /* Current instruction offset in the trampoline. */
  uintptr_t jmp_dest; /* Furthest destination of an internal jump. */
  bool      finished; /* Trampoline is complete. */

  uint8_t   code[16]; /* Rewritten current instruction. */
};

/* Encode the jump, call, or conditional jump (with the condition code) to
 * the destination into the builder's code and return its size. The address
 * is that of the rewritten instruction in the trampoline.
 */
static unsigned int
encode_jmp (struct builder* b, uintptr_t dest, uintptr_t address)
{
#if defined(_M_X64) || defined(__x86_64__)
  struct mh_jmp_abs j = {0xFF, 0x25, 0x00000000, dest};
  (void) address;
#else
  struct mh_jmp_rel j = {
    0xE9, (uint32_t) (dest - (address + sizeof (struct mh_jmp_rel)))};
#endif

  memcpy (b->code, &j, sizeof (j));
  return sizeof (j);
}

static unsigned int
encode_call (struct builder* b, uintptr_t dest, uintptr_t address)
{
#if defined(_M_X64) || defined(__x86_64__)
  struct mh_call_abs c = {0xFF, 0x15, 0x00000002, 0xEB, 0x08, dest};
  (void) address;
#else
  struct mh_jmp_rel c = {
    0xE8, (uint32_t) (dest - (address + sizeof (struct mh_jmp_rel)))};
#endif

  memcpy (b->code, &c, sizeof (c));
  return sizeof (c);
}

static unsigned int
encode_jcc (struct builder* b,
            uint8_t condition,
            uintptr_t dest,
            uintptr_t address)
{
#if defined(_M_X64) || defined(__x86_64__)
  /* Jump over the absolute jump with the inverted condition.
   */
  struct mh_jcc_abs j = {
    0x71 ^ condition, 0x0E, 0xFF, 0x25, 0x00000000, dest};
  (void) address;
#else
  struct mh_jcc_rel j = {
    0x0F,
    0x80 | condition,
    (uint32_t) (dest - (address + sizeof (struct mh_jcc_rel)))};
#endif

  memcpy (b->code, &j, sizeof (j));
  return sizeof (j);
}

#if defined(_M_X64) || defined(__x86_64__)
/* Return the size of the instruction's immediate operands. Note that the
 * HDE64_F_IMM* flags are the sizes shifted left by 2 and enter has two
 * immediates.
 */
static unsigned int
immediate_size (const instruction* i)
{
  return (i->flags & (HDE64_F_IMM8  | HDE64_F_IMM16 |
                      HDE64_F_IMM32 | HDE64_F_IMM64)) >> 2;
}
#endif

/* Return true if the destination is within the part of the target that
 * the hook overwrites.
 */
static bool
internal (const struct builder* b, uintptr_t dest)
{
  uintptr_t t = (uintptr_t) b->trampoline->target;
  return t <= dest && dest < t + sizeof (struct mh_jmp_rel);
}

/* Rewrite the instruction at the address in the target for the address in
 * the trampoline. Set the code to copy into the trampoline and its size,
 * which is initially the instruction length. Return false if the
 * instruction cannot be relocated.
 */
static bool
relocate (struct builder* b,
          const instruction* i,
          uintptr_t old_address,
          uintptr_t new_address,
          const void** code,
          unsigned int* size)
{
  *code = (const void*) old_address;

  if (b->old_pos >= sizeof (struct mh_jmp_rel))
  {
    /* The trampoline is long enough, so complete it with the jump to the
     * rest of the target.
     */
    *code = b->code;
    *size = encode_jmp (b, old_address, new_address);
    b->finished = true;
  }
#if defined(_M_X64) || defined(__x86_64__)
  else if ((i->modrm & 0xC7) == 0x05)
  {
    /* RIP-relative addressing (ModR/M 00???101). Adjust the displacement,
     * which precedes the immediate operands, for the new address.
     *
     * HDE decodes the address size prefix (67) as 16-bit addressing, which
     * has no displacement for this ModR/M. Refuse such an instruction since
     * its displacement position is unknown.
     */
    if ((i->flags & HDE64_F_DISP32) == 0)
      return false;

    uint32_t d = (uint32_t) ((old_address + i->len +
                              offset32 (i->disp.disp32)) -
                             (new_address + i->len));

    memcpy (b->code, (const void*) old_address, *size);
    memcpy (b->code + i->len - immediate_size (i) - 4, &d, sizeof (d));
    *code = b->code;

    /* An indirect jmp (FF /4) completes the function.
     */
    if (i->opcode == 0xFF && i->modrm_reg == 4)
      b->finished = true;
  }
#endif
  else if (i->opcode == 0xE8)
  {
    /* Relative call.
     */
    uintptr_t dest = old_address + i->len + offset32 (i->imm.imm32);

    *code = b->code;
    *size = encode_call (b, dest, new_address);
  }
  else if ((i->opcode & 0xFD) == 0xE9)
  {
    /* Relative jmp (EB or E9).
     */
    uintptr_t dest = old_address + i->len;

    if (i->opcode == 0xEB)
      dest += offset8 (i->imm.imm8);
    else
      dest += offset32 (i->imm.imm32);

    if (internal (b, dest))
    {
      if (b->jmp_dest < dest)
        b->jmp_dest = dest;
    }
    else
    {
      *code = b->code;
      *size = encode_jmp (b, dest, new_address);

      /* Complete the function unless the jump is within a branch.
       */
      b->finished = old_address >= b->jmp_dest;
    }
  }
  else if ((i->opcode  & 0xF0) == 0x70 ||
           (i->opcode  & 0xFC) == 0xE0 ||
           (i->opcode2 & 0xF0) == 0x80)
  {
    /* Relative jcc, as well as loop, loopz, loopnz, jcxz, and jecxz
     * (E0-E3), which only have the 8-bit form.
     */
    bool loop = (i->opcode & 0xFC) == 0xE0;
    uintptr_t dest = old_address + i->len;

    if ((i->opcode & 0xF0) == 0x70 || loop)
      dest += offset8 (i->imm.imm8);
    else
      dest += offset32 (i->imm.imm32);

    if (internal (b, dest))
    {
      if (b->jmp_dest < dest)
        b->jmp_dest = dest;
    }
    else if (loop)
      return false;
    else
    {
      uint8_t c = (i->opcode != 0x0F ? i->opcode : i->opcode2) & 0x0F;

      *code = b->code;
      *size = encode_jcc (b, c, dest, new_address);
    }
  }
  else if ((i->opcode & 0xFE) == 0xC2)
  {
    /* ret (C2 or C3) completes the function unless it is within a branch.
     */
    b->finished = old_address >= b->jmp_dest;
  }

  return true;
}

/* Return true if the bytes are all the same padding byte (00, 90, or CC).
 */
static bool
code_padding (const uint8_t* p, unsigned int n)
{
  if (p[0] != 0x00 && p[0] != 0x90 && p[0] != 0xCC)
    return false;

  for (unsigned int i = 1; i < n; ++i)
  {
    if (p[i] != p[0])
      return false;
  }

  return true;
}

bool
mh_create_trampoline (struct mh_trampoline* t)
{
  struct builder b = {.trampoline = t};

  t->patch_above = false;
  t->ip_count = 0;

  do
  {
    uintptr_t old_address = (uintptr_t) t->target + b.old_pos;
    uintptr_t new_address = (uintptr_t) t->trampoline + b.new_pos;

    instruction i;
    unsigned int size = decode ((const void*) old_address, &i);

    if (i.flags & INSTRUCTION_ERROR)
      return false;

    const void* code;
    if (!relocate (&b, &i, old_address, new_address, &code, &size))
      return false;

    /* A rewritten instruction cannot be longer within a branch, since the
     * branch offsets would change.
     */
    if (old_address < b.jmp_dest && size != i.len)
      return false;

    if (b.new_pos + size > TRAMPOLINE_MAX_SIZE)
      return false;

    /* The trampoline is complete once it covers the hook's jump, so it
     * holds at most one instruction for each of the jump's 5 bytes and the
     * jump back to the rest of the target, which fit into the boundaries.
     */
    assert (t->ip_count < sizeof (t->old_ips));

    t->old_ips[t->ip_count] = b.old_pos;
    t->new_ips[t->ip_count] = b.new_pos;
    t->ip_count++;

    memcpy ((uint8_t*) t->trampoline + b.new_pos, code, size);
    b.new_pos = (uint8_t) (b.new_pos + size);
    b.old_pos = (uint8_t) (b.old_pos + i.len);
  }
  while (!b.finished);

  /* If the function is shorter than the hook's jump, then the rest must be
   * padding. If there is no room for even a short jump, then the hook
   * jumps to a long jump placed into the padding above the function (hot
   * patch area).
   */
  const uint8_t* p = (const uint8_t*) t->target;

  if (b.old_pos < sizeof (struct mh_jmp_rel) &&
      !code_padding (p + b.old_pos, sizeof (struct mh_jmp_rel) - b.old_pos))
  {
    if (b.old_pos < sizeof (struct mh_jmp_rel_short) &&
        !code_padding (p + b.old_pos,
                       sizeof (struct mh_jmp_rel_short) - b.old_pos))
      return false;

    if (!mh_executable_address (p - sizeof (struct mh_jmp_rel)))
      return false;

    if (!code_padding (p - sizeof (struct mh_jmp_rel),
                       sizeof (struct mh_jmp_rel)))
      return false;

    t->patch_above = true;
  }

#if defined(_M_X64) || defined(__x86_64__)
  /* The relay jumps to the detour. The hook's relative jump reaches it
   * since it is in the same slot as the trampoline.
   */
  t->relay = (uint8_t*) t->trampoline + b.new_pos;
  encode_jmp (&b, (uintptr_t) t->detour, (uintptr_t) t->relay);
  memcpy (t->relay, b.code, sizeof (struct mh_jmp_abs));
#endif

  return true;
}
