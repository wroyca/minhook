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

#include <Zydis/Zydis.h>

#include <libminhook/buffer.h>

typedef ZydisDecodedInstruction instruction;

#if defined(_M_X64) || defined(__x86_64__)
#  define MACHINE_MODE ZYDIS_MACHINE_MODE_LONG_64
#  define STACK_WIDTH  ZYDIS_STACK_WIDTH_64

/* Maximum size of the trampoline. The relay follows it in the same slot.
 */
#  define TRAMPOLINE_MAX_SIZE                                                \
  (MH_MEMORY_SLOT_SIZE - sizeof (struct mh_jmp_abs))
#else
#  define MACHINE_MODE ZYDIS_MACHINE_MODE_LEGACY_32
#  define STACK_WIDTH  ZYDIS_STACK_WIDTH_32

/* Without the relay the trampoline has the whole slot.
 */
#  define TRAMPOLINE_MAX_SIZE MH_MEMORY_SLOT_SIZE
#endif

/* Trampoline builder state.
 */
struct builder
{
  struct mh_trampoline* trampoline;

  uint8_t   old_pos;  /* Current instruction offset in the target. */
  uint8_t   new_pos;  /* Current instruction offset in the trampoline. */
  uintptr_t jmp_dest; /* Furthest destination of an internal branch. */
  bool      finished; /* Trampoline is complete. */

  uint8_t   code[16]; /* Rewritten current instruction. */
};

/* Encode the branch to the destination into the builder's code and return
 * its size. The address is that of the branch in the trampoline.
 *
 * On x64 we encode absolute branches since the destination may be out of
 * the reach of a relative one.
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

/* Return true if the destination is within the part of the target that
 * the hook overwrites.
 */
static bool
internal (const struct builder* b, uintptr_t dest)
{
  uintptr_t t = (uintptr_t) b->trampoline->target;
  return t <= dest && dest < t + sizeof (struct mh_jmp_rel);
}

/* Keep the internal branch at the address to the destination as is. Return
 * false if the trampoline can't keep it.
 *
 * The code between such a branch and its destination must keep its length
 * in the trampoline since the branch's offset would be off otherwise. For a
 * forward branch we check this as we relocate that code (see jmp_dest). For
 * a backward branch that code is already relocated, so we compare its
 * length in the target and in the trampoline. Note that this requires the
 * destination to be an instruction boundary since otherwise we can't tell
 * where it is in the trampoline.
 */
static bool
keep_branch (struct builder* b, uintptr_t dest, uintptr_t address)
{
  if (dest > address)
  {
    if (b->jmp_dest < dest)
      b->jmp_dest = dest;

    return true;
  }

  const struct mh_trampoline* t = b->trampoline;
  unsigned int o = (unsigned int) (dest - (uintptr_t) t->target);

  /* A branch to itself has no code in between.
   */
  if (o == b->old_pos)
    return true;

  for (unsigned int i = 0; i < t->ip_count; ++i)
  {
    if (t->old_ips[i] == o)
      return b->new_pos - t->new_ips[i] == b->old_pos - o;
  }

  return false;
}

/* Return true if the instruction is jcc (7x or 0F 8x).
 *
 * We go by the opcode since the conditional branch category also includes
 * instructions such as xbegin.
 */
static bool
jcc (const instruction* i)
{
  return (i->opcode_map == ZYDIS_OPCODE_MAP_DEFAULT &&
          (i->opcode & 0xF0) == 0x70) ||
         (i->opcode_map == ZYDIS_OPCODE_MAP_0F &&
          (i->opcode & 0xF0) == 0x80);
}

/* Return true if the instruction is from the loop and jcxz family (E0 to
 * E3).
 */
static bool
loop (const instruction* i)
{
  return i->opcode_map == ZYDIS_OPCODE_MAP_DEFAULT &&
         (i->opcode & 0xFC) == 0xE0;
}

/* Return the destination of the relative branch at the address.
 */
static uintptr_t
branch_destination (const instruction* i, uintptr_t address)
{
  return address + i->length + (uintptr_t) (intptr_t) i->raw.imm[0].value.s;
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

  bool branch = i->raw.imm[0].is_relative;

  if (b->old_pos >= sizeof (struct mh_jmp_rel))
  {
    /* The trampoline is long enough, so complete it with the jump to the
     * rest of the target.
     */
    *code = b->code;
    *size = encode_jmp (b, old_address, new_address);
    b->finished = true;
  }
  else if (branch && i->operand_width == 16)
  {
    /* A relative branch with the 16-bit operand size truncates the
     * instruction pointer to 16 bits, which the rewritten branch can't
     * reproduce.
     */
    return false;
  }
#if defined(_M_X64) || defined(__x86_64__)
  else if ((i->attributes & ZYDIS_ATTRIB_HAS_MODRM) != 0 &&
           i->raw.modrm.mod == 0                       &&
           i->raw.modrm.rm == 5)
  {
    /* RIP-relative addressing (ModR/M 00???101). Adjust the displacement
     * for the new address.
     *
     * The address size prefix (67) makes the addressing EIP-relative,
     * which truncates the address to 32 bits. We refuse such an
     * instruction.
     */
    if (i->address_width != 64)
      return false;

    /* The trampoline is within 1 GiB of the target, but the displacement
     * may move the destination up to another 2 GiB away. So we refuse the
     * instruction if the destination is out of the reach of the new
     * displacement.
     */
    intptr_t d = (intptr_t) ((old_address + i->length +
                              (uintptr_t) (intptr_t) i->raw.disp.value) -
                             (new_address + i->length));

    if (d < INT32_MIN || d > INT32_MAX)
      return false;

    memcpy (b->code, (const void*) old_address, *size);
    int32_t v = (int32_t) d;
    memcpy (b->code + i->raw.disp.offset, &v, sizeof (v));
    *code = b->code;

    /* An indirect jmp completes the function.
     */
    if (i->mnemonic == ZYDIS_MNEMONIC_JMP)
      b->finished = true;
  }
#endif
  else if (branch && i->mnemonic == ZYDIS_MNEMONIC_CALL)
  {
    /* Relative call.
     */
    *code = b->code;
    *size = encode_call (b, branch_destination (i, old_address), new_address);
  }
  else if (branch && i->mnemonic == ZYDIS_MNEMONIC_JMP)
  {
    /* Relative jmp.
     */
    uintptr_t dest = branch_destination (i, old_address);

    if (internal (b, dest))
    {
      if (!keep_branch (b, dest, old_address))
        return false;
    }
    else
    {
      *code = b->code;
      *size = encode_jmp (b, dest, new_address);

      /* The jump completes the function unless it is within a branch.
       */
      b->finished = old_address >= b->jmp_dest;
    }
  }
  else if (branch && (jcc (i) || loop (i)))
  {
    /* Relative jcc or loop (see loop()). We can only keep a loop that stays
     * within the code that the hook overwrites since it has no form that
     * reaches further.
     */
    uintptr_t dest = branch_destination (i, old_address);

    if (internal (b, dest))
    {
      if (!keep_branch (b, dest, old_address))
        return false;
    }
    else if (loop (i))
      return false;
    else
    {
      /* The low nibble of the last opcode byte (7x or 0F 8x) is the
       * condition code.
       */
      *code = b->code;
      *size = encode_jcc (b, i->opcode & 0x0F, dest, new_address);
    }
  }
  else if (branch)
  {
    /* Another instruction with a relative operand (xbegin, for example)
     * needs a rewrite of its own, so we refuse it.
     */
    return false;
  }
  else if (i->mnemonic == ZYDIS_MNEMONIC_RET)
  {
    /* ret completes the function unless it is within a branch.
     */
    b->finished = old_address >= b->jmp_dest;
  }

  return true;
}

/* Return true if the bytes are all the same padding byte (00, 90, or CC)
 * in executable memory.
 *
 * Note that the bytes are next to the target function and may extend into
 * the page before or after it, which may be data or not even readable. So
 * we check the memory before reading it. The bytes span two pages at most,
 * so they are all executable if the first and the last are.
 */
static bool
padded (const uint8_t* p, size_t n)
{
  if (!mh_executable_address (p) || !mh_executable_address (p + n - 1))
    return false;

  if (p[0] != 0x00 && p[0] != 0x90 && p[0] != 0xCC)
    return false;

  for (size_t i = 1; i < n; ++i)
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

  /* Set up the decoder. It only fails for an invalid combination of the
   * machine mode and stack width or an invalid decoder mode, neither of
   * which we pass.
   *
   * The minimal decoder mode skips the semantic analysis. It still fills
   * every field that relocate() and its helpers read.
   */
  ZydisDecoder d;
  ZyanStatus s = ZydisDecoderInit (&d, MACHINE_MODE, STACK_WIDTH);
  assert (ZYAN_SUCCESS (s));

  s = ZydisDecoderEnableMode (&d, ZYDIS_DECODER_MODE_MINIMAL, ZYAN_TRUE);
  assert (ZYAN_SUCCESS (s));
  (void) s;

  do
  {
    uintptr_t old_address = (uintptr_t) t->target + b.old_pos;
    uintptr_t new_address = (uintptr_t) t->trampoline + b.new_pos;

    /* Note that the decoder may read up to the maximum instruction length
     * past the address.
     */
    instruction i;
    if (ZYAN_FAILED (ZydisDecoderDecodeInstruction (
                       &d,
                       NULL,
                       (const void*) old_address,
                       ZYDIS_MAX_INSTRUCTION_LENGTH,
                       &i)))
      return false;

    unsigned int size = i.length;

    const void* code;
    if (!relocate (&b, &i, old_address, new_address, &code, &size))
      return false;

    /* Within a branch a rewritten instruction must keep its length since
     * the branch's offsets would change otherwise.
     */
    if (old_address < b.jmp_dest && size != i.length)
      return false;

    /* Make sure the trampoline fits into the slot.
     */
    if (b.new_pos + size > TRAMPOLINE_MAX_SIZE)
      return false;

    /* The trampoline is complete once it covers the hook's jump, so it
     * holds at most one instruction for each of the jump's 5 bytes plus the
     * jump back to the rest of the target. That is 6 boundaries at most,
     * which old_ips has room for.
     */
    assert (t->ip_count < sizeof (t->old_ips));

    t->old_ips[t->ip_count] = b.old_pos;
    t->new_ips[t->ip_count] = b.new_pos;
    t->ip_count++;

    memcpy ((uint8_t*) t->trampoline + b.new_pos, code, size);
    b.new_pos = (uint8_t) (b.new_pos + size);
    b.old_pos = (uint8_t) (b.old_pos + i.length);
  }
  while (!b.finished);

  /* If the function is shorter than the hook's jump, then the rest must be
   * padding. If there is no room for even a short jump, then the hook
   * jumps to a long jump placed into the padding above the function (hot
   * patch area).
   */
  const uint8_t* p = (const uint8_t*) t->target;
  size_t n = b.old_pos;

  if (n < sizeof (struct mh_jmp_rel) &&
      !padded (p + n, sizeof (struct mh_jmp_rel) - n))
  {
    if (n < sizeof (struct mh_jmp_rel_short) &&
        !padded (p + n, sizeof (struct mh_jmp_rel_short) - n))
      return false;

    if (!padded (p - sizeof (struct mh_jmp_rel), sizeof (struct mh_jmp_rel)))
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
