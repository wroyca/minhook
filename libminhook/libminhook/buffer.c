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

#include <libminhook/buffer.h>

#include <windows.h>

#include <assert.h>
#include <stdint.h>

/* Size of a block, which is one page.
 */
#define MEMORY_BLOCK_SIZE 0x1000

/* Maximum distance between a block and the origin of its slots (1 GiB),
 * which a 32-bit relative jump reaches with room to spare.
 */
#define MAX_MEMORY_RANGE 0x40000000

/* Protections that allow executing the memory.
 */
#define PAGE_EXECUTE_FLAGS                                                   \
  (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |               \
   PAGE_EXECUTE_WRITECOPY)

/* Slot for a trampoline. A free slot links to the next free slot of its
 * block.
 */
union memory_slot
{
  union memory_slot* next;
  uint8_t buffer[MH_MEMORY_SLOT_SIZE];
};

/* Block of slots. The header occupies the first slot.
 */
struct memory_block
{
  struct memory_block* next;
  union memory_slot* free; /* First free slot. */
  unsigned int used;       /* Number of slots in use. */
};

/* Allocated blocks, the most recent first.
 */
static struct memory_block* blocks;

#if defined(_M_X64) || defined(__x86_64__)
/* System information for the block search (see get_memory_block()). It
 * stays the same for the life of the process, so we query it once.
 */
static SYSTEM_INFO system_info;
#endif

void
mh_initialize_buffer (void)
{
#if defined(_M_X64) || defined(__x86_64__)
  GetSystemInfo (&system_info);
#endif
}

void
mh_uninitialize_buffer (void)
{
  struct memory_block* b = blocks;
  blocks = NULL;

  while (b != NULL)
  {
    struct memory_block* n = b->next;
    VirtualFree (b, 0, MEM_RELEASE);
    b = n;
  }
}

/* Allocate a block at the address or, if it is NULL, anywhere. Return NULL
 * if unable to.
 */
static struct memory_block*
allocate_block (void* address)
{
  return (struct memory_block*) VirtualAlloc (address,
                                              MEMORY_BLOCK_SIZE,
                                              MEM_COMMIT | MEM_RESERVE,
                                              PAGE_EXECUTE_READWRITE);
}

#if defined(_M_X64) || defined(__x86_64__)

/* Return the closest free region below the address and at or above the
 * minimum or NULL if there is none.
 *
 * We search in the allocation granularity steps since VirtualAlloc() rounds
 * the address of a new allocation down to the granularity.
 */
static void*
find_previous_free_region (void* address, uintptr_t minimum, DWORD granularity)
{
  uintptr_t a = (uintptr_t) address;

  a -= a % granularity; /* Round down to the granularity. */
  a -= granularity;     /* Start from the previous multiple. */

  while (a >= minimum)
  {
    /* The address is between the minimum and the origin, both within the
     * user address space, so the query succeeds.
     */
    MEMORY_BASIC_INFORMATION i;
    SIZE_T n = VirtualQuery ((void*) a, &i, sizeof (i));
    assert (n != 0);
    (void) n;

    if (i.State == MEM_FREE)
      return (void*) a;

    /* The system allocates nothing below the minimum application address,
     * which is the allocation granularity, so the region's allocation base
     * is at least that and the next address doesn't wrap around.
     */
    assert ((uintptr_t) i.AllocationBase >= granularity);

    a = (uintptr_t) i.AllocationBase - granularity;
  }

  return NULL;
}

/* Return the closest free region above the address and at or below the
 * maximum or NULL if there is none. See find_previous_free_region() for
 * details.
 */
static void*
find_next_free_region (void* address, uintptr_t maximum, DWORD granularity)
{
  uintptr_t a = (uintptr_t) address;

  a -= a % granularity; /* Round down to the granularity. */
  a += granularity;     /* Start from the next multiple. */

  while (a <= maximum)
  {
    /* The address is between the origin and the maximum, both within the
     * user address space, so the query succeeds.
     */
    MEMORY_BASIC_INFORMATION i;
    SIZE_T n = VirtualQuery ((void*) a, &i, sizeof (i));
    assert (n != 0);
    (void) n;

    if (i.State == MEM_FREE)
      return (void*) a;

    a = (uintptr_t) i.BaseAddress + i.RegionSize;

    /* Round up to the granularity. */
    a += granularity - 1;
    a -= a % granularity;
  }

  return NULL;
}

/* Allocate a block in the closest free region below the origin and at or
 * above the minimum.
 */
static struct memory_block*
allocate_block_below (void* origin, uintptr_t minimum, DWORD granularity)
{
  for (void* a = origin; (uintptr_t) a >= minimum; )
  {
    a = find_previous_free_region (a, minimum, granularity);
    if (a == NULL)
      break;

    struct memory_block* b = allocate_block (a);
    if (b != NULL)
      return b;
  }

  return NULL;
}

/* Allocate a block in the closest free region above the origin and at or
 * below the maximum.
 */
static struct memory_block*
allocate_block_above (void* origin, uintptr_t maximum, DWORD granularity)
{
  for (void* a = origin; (uintptr_t) a <= maximum; )
  {
    a = find_next_free_region (a, maximum, granularity);
    if (a == NULL)
      break;

    struct memory_block* b = allocate_block (a);
    if (b != NULL)
      return b;
  }

  return NULL;
}

#endif

/* Link all the slots after the block header into the free list and add
 * the block to the allocated blocks.
 */
static void
register_block (struct memory_block* b)
{
  union memory_slot* s = (union memory_slot*) b + 1;

  b->free = NULL;
  b->used = 0;

  do
  {
    s->next = b->free;
    b->free = s;
    s++;
  }
  while ((uintptr_t) s - (uintptr_t) b <=
         MEMORY_BLOCK_SIZE - MH_MEMORY_SLOT_SIZE);

  b->next = blocks;
  blocks = b;
}

/* Return a block with a free slot that is reachable from the origin,
 * allocating a new one if necessary. Return NULL if unable to allocate.
 */
static struct memory_block*
get_memory_block (void* origin)
{
  struct memory_block* b;

#if defined(_M_X64) || defined(__x86_64__)
  const SYSTEM_INFO* si = &system_info;

  uintptr_t o = (uintptr_t) origin;
  uintptr_t minimum = (uintptr_t) si->lpMinimumApplicationAddress;
  uintptr_t maximum = (uintptr_t) si->lpMaximumApplicationAddress;

  /* Limit the range to MAX_MEMORY_RANGE around the origin and make room
   * for a whole block at the top.
   */
  if (o > MAX_MEMORY_RANGE && minimum < o - MAX_MEMORY_RANGE)
    minimum = o - MAX_MEMORY_RANGE;

  if (maximum > o + MAX_MEMORY_RANGE)
    maximum = o + MAX_MEMORY_RANGE;

  maximum -= MEMORY_BLOCK_SIZE - 1;
#endif

  /* Look for a block within the range that has a free slot.
   */
  for (b = blocks; b != NULL; b = b->next)
  {
#if defined(_M_X64) || defined(__x86_64__)
    if ((uintptr_t) b < minimum || (uintptr_t) b >= maximum)
      continue;
#endif
    if (b->free != NULL)
      return b;
  }

  /* Allocate a new block, trying below the origin first.
   */
#if defined(_M_X64) || defined(__x86_64__)
  b = allocate_block_below (origin, minimum, si->dwAllocationGranularity);

  if (b == NULL)
    b = allocate_block_above (origin, maximum, si->dwAllocationGranularity);
#else
  /* On x86 a relative jump reaches the whole address space, so a block can
   * be anywhere.
   */
  (void) origin;
  b = allocate_block (NULL);
#endif

  if (b != NULL)
    register_block (b);

  return b;
}

void*
mh_allocate_buffer (void* origin)
{
  struct memory_block* b = get_memory_block (origin);
  if (b == NULL)
    return NULL;

  union memory_slot* s = b->free;
  b->free = s->next;
  b->used++;

  return s;
}

void
mh_free_buffer (void* buffer)
{
  uintptr_t a = ((uintptr_t) buffer / MEMORY_BLOCK_SIZE) * MEMORY_BLOCK_SIZE;
  struct memory_block* p = NULL; /* Previous block. */

  for (struct memory_block* b = blocks; b != NULL; p = b, b = b->next)
  {
    if ((uintptr_t) b != a)
      continue;

    union memory_slot* s = (union memory_slot*) buffer;
    s->next = b->free;
    b->free = s;
    b->used--;

    /* Release the block if it has no slots in use.
     */
    if (b->used == 0)
    {
      if (p != NULL)
        p->next = b->next;
      else
        blocks = b->next;

      VirtualFree (b, 0, MEM_RELEASE);
    }

    break;
  }
}

bool
mh_executable_address (const void* address)
{
  MEMORY_BASIC_INFORMATION i;
  if (VirtualQuery (address, &i, sizeof (i)) == 0)
    return false;

  return i.State == MEM_COMMIT && (i.Protect & PAGE_EXECUTE_FLAGS) != 0;
}
