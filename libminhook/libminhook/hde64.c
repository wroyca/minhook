/*
 * Hacker Disassembler Engine 64 C
 * Copyright (c) 2008-2009, Vyacheslav Patkov.
 * All rights reserved.
 *
 */

#include <libminhook/hde64.h>

#include <string.h>  /* memset(), memcpy() */
#include <stdbool.h>

#include <libminhook/table64.h>

static inline uint16_t
load16 (const uint8_t* p)
{
  uint16_t r;
  memcpy (&r, p, sizeof (r));
  return r;
}

static inline uint32_t
load32 (const uint8_t* p)
{
  uint32_t r;
  memcpy (&r, p, sizeof (r));
  return r;
}

static inline uint64_t
load64 (const uint8_t* p)
{
  uint64_t r;
  memcpy (&r, p, sizeof (r));
  return r;
}

/* If the byte is a prefix, then record it in the instruction and return
 * its PRE_* flag. Otherwise, return 0.
 */
static uint8_t
prefix (struct hde64_instruction* i, uint8_t c)
{
  switch (c)
  {
    case 0xf3:
    {
      i->p_rep = c;
      return PRE_F3;
    }
    case 0xf2:
    {
      i->p_rep = c;
      return PRE_F2;
    }
    case 0xf0:
    {
      i->p_lock = c;
      return PRE_LOCK;
    }
    case 0x26:
    case 0x2e:
    case 0x36:
    case 0x3e:
    case 0x64:
    case 0x65:
    {
      i->p_seg = c;
      return PRE_SEG;
    }
    case 0x66:
    {
      i->p_66 = c;
      return PRE_66;
    }
    case 0x67:
    {
      i->p_67 = c;
      return PRE_67;
    }
  }

  return 0;
}

/* Return true if the lock prefix is valid for the opcode with the ModR/M
 * reg field.
 */
static bool
lock_valid (const struct hde64_instruction* i, uint8_t opcode, uint8_t reg)
{
  const uint8_t* t;
  const uint8_t* e;

  if (i->opcode2)
  {
    t = hde64_table + DELTA_OP2_LOCK_OK;
    e = t + DELTA_OP_ONLY_MEM - DELTA_OP2_LOCK_OK;
  }
  else
  {
    t = hde64_table + DELTA_OP_LOCK_OK;
    e = t + DELTA_OP2_LOCK_OK - DELTA_OP_LOCK_OK;
    opcode &= 0xfe;
  }

  /* The table has an opcode and a reg mask per entry.
   */
  for (; t != e; t++)
  {
    if (*t++ == opcode)
      return !((*t << reg) & 0x80);
  }

  return false;
}

/* Return true if the ModR/M operands are invalid for the opcode given the
 * prefixes. Note that the control and debug register moves always have
 * register operands, so set mod to 3 for them.
 */
static bool
operand_error (const struct hde64_instruction* i,
               uint8_t opcode,
               uint8_t pref,
               uint8_t* mod,
               uint8_t reg)
{
  if (i->opcode2)
  {
    switch (opcode)
    {
      case 0x20:
      case 0x22:
      {
        *mod = 3;
        return reg > 4 || reg == 1;
      }
      case 0x21:
      case 0x23:
      {
        *mod = 3;
        return reg == 4 || reg == 5;
      }
    }
  }
  else
  {
    switch (opcode)
    {
      case 0x8c: return reg > 5;
      case 0x8e: return reg == 1 || reg > 5;
    }
  }

  if (*mod == 3)
  {
    const uint8_t* t;
    const uint8_t* e;

    if (i->opcode2)
    {
      t = hde64_table + DELTA_OP2_ONLY_MEM;
      e = t + sizeof (hde64_table) - DELTA_OP2_ONLY_MEM;
    }
    else
    {
      t = hde64_table + DELTA_OP_ONLY_MEM;
      e = t + DELTA_OP2_ONLY_MEM - DELTA_OP_ONLY_MEM;
    }

    /* The table has an opcode, a prefix mask, and a reg mask per entry.
     */
    for (; t != e; t += 2)
    {
      if (*t++ == opcode)
        return (*t++ & pref) && !((*t << reg) & 0x80);
    }

    return false;
  }

  if (i->opcode2)
  {
    switch (opcode)
    {
      case 0x50:
      case 0xd7:
      case 0xf7: return (pref & (PRE_NONE | PRE_66)) != 0;
      case 0xd6: return (pref & (PRE_F2 | PRE_F3)) != 0;
      case 0xc5: return true;
    }
  }

  return false;
}

unsigned int
hde64_disasm (const void* code, struct hde64_instruction* i)
{
  const uint8_t* p = (const uint8_t*) code;
  const uint8_t* t = hde64_table;

  uint8_t c = 0, cflags, opcode, pref = 0, group = 0, disp_size = 0;
  bool op64 = false; /* 64-bit immediate or moffs operand. */

  memset (i, 0, sizeof (*i));

  for (unsigned int n = 16; n != 0; --n)
  {
    uint8_t f = prefix (i, c = *p++);

    if (f == 0)
      break;

    pref |= f;
  }

  i->flags = (uint32_t) pref << 23;

  if (!pref)
    pref |= PRE_NONE;

  /* REX prefix. With W, mov r64, imm64 (B8-BF) has a 64-bit immediate. A
   * second REX prefix is an invalid opcode.
   */
  bool rex_error = false;

  if ((c & 0xf0) == 0x40)
  {
    i->flags |= HDE64_F_PREFIX_REX;

    if ((i->rex_w = (c & 0xf) >> 3) && (*p & 0xf8) == 0xb8)
      op64 = true;

    i->rex_r = (c & 7) >> 2;
    i->rex_x = (c & 3) >> 1;
    i->rex_b = c & 1;

    if (((c = *p++) & 0xf0) == 0x40)
      rex_error = true;
  }

  if (rex_error)
  {
    opcode = c;
    cflags = C_ERROR;
  }
  else
  {
    if ((i->opcode = c) == 0x0f)
    {
      i->opcode2 = c = *p++;
      t += DELTA_OPCODES;
    }
    else if (c >= 0xa0 && c <= 0xa3)
    {
      /* The moffs forms have a 64-bit address, whose size the address size
       * prefix changes as if it were the operand size prefix.
       */
      op64 = true;

      if (pref & PRE_67)
        pref |= PRE_66;
      else
        pref &= (uint8_t) ~PRE_66;
    }

    opcode = c;
    cflags = t[t[opcode / 4] + (opcode % 4)];
  }

  if (cflags == C_ERROR)
  {
    i->flags |= HDE64_F_ERROR | HDE64_F_ERROR_OPCODE;
    cflags = 0;

    if ((opcode & -3) == 0x24)
      cflags++;
  }

  if (cflags & C_GROUP)
  {
    uint16_t g = load16 (t + (cflags & 0x7f));
    cflags = (uint8_t) g;
    group = (uint8_t) (g >> 8);
  }

  if (i->opcode2)
  {
    t = hde64_table + DELTA_PREFIXES;

    if (t[t[opcode / 4] + (opcode % 4)] & pref)
      i->flags |= HDE64_F_ERROR | HDE64_F_ERROR_OPCODE;
  }

  if (cflags & C_MODRM)
  {
    uint8_t m_mod, m_reg, m_rm;

    i->flags |= HDE64_F_MODRM;
    i->modrm = c = *p++;
    i->modrm_mod = m_mod = c >> 6;
    i->modrm_rm = m_rm = c & 7;
    i->modrm_reg = m_reg = (c & 0x3f) >> 3;

    if (group && ((group << m_reg) & 0x80))
      i->flags |= HDE64_F_ERROR | HDE64_F_ERROR_OPCODE;

    if (!i->opcode2 && opcode >= 0xd9 && opcode <= 0xdf)
    {
      uint8_t f = opcode - 0xd9;

      if (m_mod == 3)
      {
        t = hde64_table + DELTA_FPU_MODRM + f * 8;
        f = (uint8_t) (t[m_reg] << m_rm);
      }
      else
      {
        t = hde64_table + DELTA_FPU_REG;
        f = (uint8_t) (t[f] << m_reg);
      }

      if (f & 0x80)
        i->flags |= HDE64_F_ERROR | HDE64_F_ERROR_OPCODE;
    }

    if (pref & PRE_LOCK)
    {
      if (m_mod == 3 || !lock_valid (i, opcode, m_reg))
        i->flags |= HDE64_F_ERROR | HDE64_F_ERROR_LOCK;
    }

    if (operand_error (i, opcode, pref, &m_mod, m_reg))
      i->flags |= HDE64_F_ERROR | HDE64_F_ERROR_OPERAND;

    c = *p++;

    if (m_reg <= 1)
    {
      if (opcode == 0xf6)
        cflags |= C_IMM8;
      else if (opcode == 0xf7)
        cflags |= C_IMM_P66;
    }

    switch (m_mod)
    {
      case 0:
      {
        if (pref & PRE_67)
        {
          if (m_rm == 6)
            disp_size = 2;
        }
        else if (m_rm == 5)
          disp_size = 4;

        break;
      }
      case 1:
      {
        disp_size = 1;
        break;
      }
      case 2:
      {
        disp_size = 2;

        if (!(pref & PRE_67))
          disp_size <<= 1;

        break;
      }
    }

    if (m_mod != 3 && m_rm == 4)
    {
      i->flags |= HDE64_F_SIB;
      p++;
      i->sib = c;
      i->sib_scale = c >> 6;
      i->sib_index = (c & 0x3f) >> 3;

      if ((i->sib_base = c & 7) == 5 && !(m_mod & 1))
        disp_size = 4;
    }

    p--;

    switch (disp_size)
    {
      case 1:
      {
        i->flags |= HDE64_F_DISP8;
        i->disp.disp8 = *p;
        break;
      }
      case 2:
      {
        i->flags |= HDE64_F_DISP16;
        i->disp.disp16 = load16 (p);
        break;
      }
      case 4:
      {
        i->flags |= HDE64_F_DISP32;
        i->disp.disp32 = load32 (p);
        break;
      }
    }

    p += disp_size;
  }
  else if (pref & PRE_LOCK)
    i->flags |= HDE64_F_ERROR | HDE64_F_ERROR_LOCK;

  if ((cflags & C_IMM_P66) && (cflags & C_REL32))
  {
    /* A relative branch whose size depends on the operand size prefix.
     */
    if (pref & PRE_66)
    {
      i->flags |= HDE64_F_IMM16 | HDE64_F_RELATIVE;
      i->imm.imm16 = load16 (p);
      p += 2;
    }
    else
    {
      i->flags |= HDE64_F_IMM32 | HDE64_F_RELATIVE;
      i->imm.imm32 = load32 (p);
      p += 4;
    }
  }
  else
  {
    bool imm16 = (cflags & C_IMM16) != 0;

    if (cflags & C_IMM_P66)
    {
      if (op64)
      {
        i->flags |= HDE64_F_IMM64;
        i->imm.imm64 = load64 (p);
        p += 8;
      }
      else if (!(pref & PRE_66))
      {
        i->flags |= HDE64_F_IMM32;
        i->imm.imm32 = load32 (p);
        p += 4;
      }
      else
        imm16 = true;
    }

    if (imm16)
    {
      i->flags |= HDE64_F_IMM16;
      i->imm.imm16 = load16 (p);
      p += 2;
    }

    if (cflags & C_IMM8)
    {
      i->flags |= HDE64_F_IMM8;
      i->imm.imm8 = *p++;
    }

    if (cflags & C_REL32)
    {
      i->flags |= HDE64_F_IMM32 | HDE64_F_RELATIVE;
      i->imm.imm32 = load32 (p);
      p += 4;
    }
    else if (cflags & C_REL8)
    {
      i->flags |= HDE64_F_IMM8 | HDE64_F_RELATIVE;
      i->imm.imm8 = *p++;
    }
  }

  if ((i->len = (uint8_t) (p - (const uint8_t*) code)) > 15)
  {
    i->flags |= HDE64_F_ERROR | HDE64_F_ERROR_LENGTH;
    i->len = 15;
  }

  return i->len;
}
