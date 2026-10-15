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

#include <libminhook/minhook.h>

#include <windows.h>
#include <winternl.h> /* NTSTATUS, NT_SUCCESS() */

#include <limits.h> /* UINT_MAX */
#include <stdint.h>
#include <string.h> /* memcpy() */
#include <stdbool.h>

#include <libminhook/buffer.h>
#include <libminhook/trampoline.h>

/* mh_create_hook_api_ex() copies a FARPROC into a void*, so the two must
 * have the same size. We check this with an array whose size turns negative
 * if they differ since MSVC only supports _Static_assert in its C11 mode,
 * which build2 doesn't enable.
 */
typedef char
mh_farproc_size_check[sizeof (FARPROC) == sizeof (void*) ? 1 : -1];

/* Initial capacities of the hook and the thread lists.
 */
#define INITIAL_HOOK_CAPACITY   32
#define INITIAL_THREAD_CAPACITY 128

/* Positions that denote no hook (see find_hook_entry()) and all the hooks
 * (see freeze()). They can share the value since no function takes both.
 */
#define INVALID_HOOK_POS UINT_MAX
#define ALL_HOOKS_POS    UINT_MAX

/* Initial capacity of the retirement list and the position that denotes no
 * retirement (see find_retirement()).
 */
#define INITIAL_RETIREMENT_CAPACITY 32
#define INVALID_RETIREMENT_POS      UINT_MAX

/* Open the process's thread that follows the thread (or the first one if
 * thread is NULL) with the access rights and store its handle in next.
 * Return NO_MORE_THREADS after the last thread.
 *
 * ntdll exports this function since Windows Vista. We declare it ourselves
 * since no Win32 header does.
 */
NTSYSAPI NTSTATUS NTAPI
NtGetNextThread (HANDLE process,
                 HANDLE thread,
                 ACCESS_MASK access,
                 ULONG attributes,
                 ULONG flags,
                 PHANDLE next);

/* Status that NtGetNextThread() returns after the last thread. This is
 * STATUS_NO_MORE_ENTRIES, which we spell out since ntstatus.h redefines the
 * status macros of winnt.h.
 */
#define NO_MORE_THREADS ((NTSTATUS) 0x8000001AL)

/* Access rights that freezing a thread needs (see freeze()).
 */
#define THREAD_ACCESS                                                        \
  (THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION |   \
   THREAD_SET_CONTEXT)

/* Size of a page, which is the unit of the memory protection.
 */
#define PAGE_SIZE 0x1000

/* Change that is being applied to the hooks. With ACTION_APPLY_QUEUED each
 * hook takes its queued state.
 */
enum action
{
  ACTION_DISABLE,
  ACTION_ENABLE,
  ACTION_APPLY_QUEUED
};

/* Hook of a target function.
 */
struct hook_entry
{
  void*   target;     /* Target function. */
  void*   detour;     /* Detour or, on x64, relay function. */
  void*   trampoline; /* Trampoline function. */
  uint8_t backup[8];  /* Code that the hook overwrites. */

  uint8_t patch_above  : 1; /* Jump goes into the hot patch area. */
  uint8_t enabled      : 1;
  uint8_t queue_enable : 1; /* Queued state (see mh_apply_queued()). */

  uint8_t ip_count;   /* Number of instruction boundaries. */
  uint8_t old_ips[8]; /* Boundaries in the target function. */
  uint8_t new_ips[8]; /* Boundaries in the trampoline. */
};

/* Threads that are suspended while the hooks are patched or a trampoline
 * is reclaimed. A NULL handle is a thread that could not be suspended.
 *
 * Note that the list comes from the process heap since mh_reclaim() also
 * suspends the threads while the library is not initialized.
 */
struct frozen_threads
{
  HANDLE*      items;
  unsigned int capacity;
  unsigned int size;
};

/* Spin lock that serializes the API calls (see lock()).
 */
static volatile LONG locked = FALSE;

/* Library's private heap, which is not NULL while the library is
 * initialized.
 */
static HANDLE heap = NULL;

/* Hooks in the order of their creation, except that removing one moves the
 * last hook into its place.
 */
static struct
{
  struct hook_entry* items;
  unsigned int       capacity;
  unsigned int       size;
} hooks;

/* Trampoline that removing its hook retired (see mh_remove_hook()).
 */
struct retirement
{
  mh_retirement_id id;
  void*            trampoline;
};

/* Retired trampolines in the order of their retirement, except that
 * reclaiming one moves the last into its place.
 *
 * Note that the list comes from the process heap since it outlives the
 * library's heap (see mh_reclaim()).
 */
static struct
{
  struct retirement* items;
  unsigned int       capacity;
  unsigned int       size;
} retirements;

/* Id of the next retirement. It persists across initializations so that
 * an id is never issued twice.
 */
static mh_retirement_id next_retirement_id = 1;

/* Return the target's hook position or INVALID_HOOK_POS if not found.
 */
static unsigned int
find_hook_entry (void* target)
{
  for (unsigned int i = 0; i < hooks.size; ++i)
  {
    if ((uintptr_t) target == (uintptr_t) hooks.items[i].target)
      return i;
  }

  return INVALID_HOOK_POS;
}

/* Return a new uninitialized hook entry or NULL if unable to allocate.
 */
static struct hook_entry*
add_hook_entry (void)
{
  if (hooks.items == NULL)
  {
    hooks.capacity = INITIAL_HOOK_CAPACITY;
    hooks.items = (struct hook_entry*) HeapAlloc (
      heap, 0, hooks.capacity * sizeof (struct hook_entry));

    if (hooks.items == NULL)
      return NULL;
  }
  else if (hooks.size >= hooks.capacity)
  {
    struct hook_entry* p = (struct hook_entry*) HeapReAlloc (
      heap, 0, hooks.items, hooks.capacity * 2 * sizeof (struct hook_entry));

    if (p == NULL)
      return NULL;

    hooks.capacity *= 2;
    hooks.items = p;
  }

  return &hooks.items[hooks.size++];
}

/* Delete the entry by moving the last entry into its position. Shrink the
 * list if it is at most half full, keeping it as is if unable to.
 */
static void
delete_hook_entry (unsigned int pos)
{
  if (pos < hooks.size - 1)
    hooks.items[pos] = hooks.items[hooks.size - 1];

  hooks.size--;

  if (hooks.capacity / 2 >= INITIAL_HOOK_CAPACITY &&
      hooks.capacity / 2 >= hooks.size)
  {
    struct hook_entry* p = (struct hook_entry*) HeapReAlloc (
      heap, 0, hooks.items, hooks.capacity / 2 * sizeof (struct hook_entry));

    if (p == NULL)
      return;

    hooks.capacity /= 2;
    hooks.items = p;
  }
}

/* Return the position of the retirement with the id or
 * INVALID_RETIREMENT_POS if not found.
 */
static unsigned int
find_retirement (mh_retirement_id id)
{
  for (unsigned int i = 0; i < retirements.size; ++i)
  {
    if (retirements.items[i].id == id)
      return i;
  }

  return INVALID_RETIREMENT_POS;
}

/* Make room for one more retirement. Return false if unable to allocate.
 */
static bool
reserve_retirement (void)
{
  if (retirements.items == NULL)
  {
    retirements.items = (struct retirement*) HeapAlloc (
      GetProcessHeap (),
      0,
      INITIAL_RETIREMENT_CAPACITY * sizeof (struct retirement));

    if (retirements.items == NULL)
      return false;

    retirements.capacity = INITIAL_RETIREMENT_CAPACITY;
  }
  else if (retirements.size >= retirements.capacity)
  {
    struct retirement* p = (struct retirement*) HeapReAlloc (
      GetProcessHeap (),
      0,
      retirements.items,
      retirements.capacity * 2 * sizeof (struct retirement));

    if (p == NULL)
      return false;

    retirements.capacity *= 2;
    retirements.items = p;
  }

  return true;
}

/* Delete the retirement by moving the last retirement into its position.
 * Free the list once it is empty.
 */
static void
delete_retirement (unsigned int pos)
{
  if (pos < retirements.size - 1)
    retirements.items[pos] = retirements.items[retirements.size - 1];

  if (--retirements.size == 0)
  {
    HeapFree (GetProcessHeap (), 0, retirements.items);

    retirements.items = NULL;
    retirements.capacity = 0;
  }
}

/* Return the hook's state that the action results in.
 */
static bool
target_state (const struct hook_entry* h, enum action a)
{
  switch (a)
  {
    case ACTION_DISABLE:      return false;
    case ACTION_ENABLE:       return true;
    case ACTION_APPLY_QUEUED: break;
  }

  return h->queue_enable;
}

/* Map the instruction pointer within the trampoline or the relay (or the
 * hot patch area) to the target function. Return 0 if it is outside.
 */
static uintptr_t
find_old_ip (const struct hook_entry* h, uintptr_t ip)
{
  if (h->patch_above &&
      ip == (uintptr_t) h->target - sizeof (struct mh_jmp_rel))
    return (uintptr_t) h->target;

  for (unsigned int i = 0; i < h->ip_count; ++i)
  {
    if (ip == (uintptr_t) h->trampoline + h->new_ips[i])
      return (uintptr_t) h->target + h->old_ips[i];
  }

#if defined(_M_X64) || defined(__x86_64__)
  if (ip == (uintptr_t) h->detour)
    return (uintptr_t) h->target;
#endif

  return 0;
}

/* Map the instruction pointer within the target function to the
 * trampoline. Return 0 if it is outside.
 */
static uintptr_t
find_new_ip (const struct hook_entry* h, uintptr_t ip)
{
  for (unsigned int i = 0; i < h->ip_count; ++i)
  {
    if (ip == (uintptr_t) h->target + h->old_ips[i])
      return (uintptr_t) h->trampoline + h->new_ips[i];
  }

  return 0;
}

/* If the suspended thread is within the code that the action on the hook
 * at the position (or on all the hooks) patches, then move its
 * instruction pointer to the equivalent instruction. Leave the thread where
 * it is if unable to read its context.
 */
static void
process_thread_ips (HANDLE thread, unsigned int pos, enum action a)
{
  CONTEXT c;
  c.ContextFlags = CONTEXT_CONTROL;

  if (!GetThreadContext (thread, &c))
    return;

#if defined(_M_X64) || defined(__x86_64__)
  DWORD64* ip = &c.Rip;
#else
  DWORD* ip = &c.Eip;
#endif

  unsigned int n;

  if (pos == ALL_HOOKS_POS)
  {
    pos = 0;
    n = hooks.size;
  }
  else
    n = pos + 1;

  for (; pos < n; ++pos)
  {
    const struct hook_entry* h = &hooks.items[pos];
    bool enable = target_state (h, a);

    if (h->enabled == enable)
      continue;

    uintptr_t p = enable ? find_new_ip (h, *ip) : find_old_ip (h, *ip);

    if (p != 0)
    {
      *ip = p;
      SetThreadContext (thread, &c);
    }
  }
}

/* Append the thread handle. Return false if unable to allocate.
 */
static bool
append_thread (struct frozen_threads* ts, HANDLE thread)
{
  if (ts->items == NULL)
  {
    ts->capacity = INITIAL_THREAD_CAPACITY;
    ts->items = (HANDLE*) HeapAlloc (GetProcessHeap (),
                                     0,
                                     ts->capacity * sizeof (HANDLE));

    if (ts->items == NULL)
      return false;
  }
  else if (ts->size >= ts->capacity)
  {
    ts->capacity *= 2;

    HANDLE* p = (HANDLE*) HeapReAlloc (
      GetProcessHeap (), 0, ts->items, ts->capacity * sizeof (HANDLE));

    if (p == NULL)
      return false;

    ts->items = p;
  }

  ts->items[ts->size++] = thread;
  return true;
}

/* Append the handles of the process's threads other than the current one.
 * Return false if unable to.
 *
 * NtGetNextThread() walks only the process's own threads and opens each of
 * them for us. It takes the previous thread to find the next one, so we
 * close the current thread's handle only once past it.
 */
static bool
collect_threads (struct frozen_threads* ts)
{
  DWORD self = GetCurrentThreadId ();
  HANDLE p = NULL; /* Previous thread. */
  HANDLE c = NULL; /* Current thread, which we close once past it. */

  for (;;)
  {
    HANDLE t;
    NTSTATUS s = NtGetNextThread (
      GetCurrentProcess (), p, THREAD_ACCESS, 0, 0, &t);

    if (c != NULL)
    {
      CloseHandle (c);
      c = NULL;
    }

    if (!NT_SUCCESS (s))
      return s == NO_MORE_THREADS;

    if (GetThreadId (t) == self)
      c = t;
    else if (!append_thread (ts, t))
    {
      CloseHandle (t);
      return false;
    }

    p = t;
  }
}

/* Collect the handles of the process's threads other than the current one.
 * Return false if unable to, closing the handles collected so far.
 */
static bool
enumerate_threads (struct frozen_threads* ts)
{
  if (collect_threads (ts))
    return true;

  for (unsigned int i = 0; i < ts->size; ++i)
    CloseHandle (ts->items[i]);

  if (ts->items != NULL)
  {
    HeapFree (GetProcessHeap (), 0, ts->items);
    ts->items = NULL;
  }

  return false;
}

/* Suspend the process's other threads, leaving alone those that can't be
 * suspended. Return MH_ERROR_MEMORY_ALLOC if unable to enumerate the
 * threads.
 */
static enum mh_status
freeze (struct frozen_threads* ts)
{
  ts->items = NULL;
  ts->capacity = 0;
  ts->size = 0;

  if (!enumerate_threads (ts))
    return MH_ERROR_MEMORY_ALLOC;

  for (unsigned int i = 0; i < ts->size; ++i)
  {
    HANDLE t = ts->items[i];

    if (SuspendThread (t) == 0xFFFFFFFF)
    {
      CloseHandle (t);
      ts->items[i] = NULL;
    }
  }

  return MH_OK;
}

/* Move the suspended threads that are within the code that the action on
 * the hook at the position (or on all the hooks) patches (see
 * process_thread_ips()).
 */
static void
move_threads (const struct frozen_threads* ts, unsigned int pos, enum action a)
{
  for (unsigned int i = 0; i < ts->size; ++i)
  {
    HANDLE t = ts->items[i];

    if (t != NULL)
      process_thread_ips (t, pos, a);
  }
}

/* Resume and close the suspended threads and free the list.
 */
static void
unfreeze (struct frozen_threads* ts)
{
  if (ts->items == NULL)
    return;

  for (unsigned int i = 0; i < ts->size; ++i)
  {
    HANDLE t = ts->items[i];

    if (t == NULL)
      continue;

    ResumeThread (t);
    CloseHandle (t);
  }

  HeapFree (GetProcessHeap (), 0, ts->items);
}

/* Return the number of the code's bytes that are on the page of its first
 * byte.
 */
static size_t
first_page_size (const uint8_t* p, size_t n)
{
  size_t r = PAGE_SIZE - (uintptr_t) p % PAGE_SIZE;
  return r < n ? r : n;
}

/* Make the code writable and store the previous protection of each of its
 * pages. Return false if unable to, leaving the protection as it was.
 *
 * VirtualProtect() returns the previous protection of the first page only,
 * so we change one page at a time since the pages may differ. The code that
 * a hook patches is at most 7 bytes long and so spans two pages at most.
 */
static bool
unprotect (uint8_t* p, size_t n, DWORD protect[2])
{
  size_t m = first_page_size (p, n);

  if (!VirtualProtect (p, m, PAGE_EXECUTE_READWRITE, &protect[0]))
    return false;

  if (m != n &&
      !VirtualProtect (p + m, n - m, PAGE_EXECUTE_READWRITE, &protect[1]))
  {
    VirtualProtect (p, m, protect[0], &protect[0]);
    return false;
  }

  return true;
}

/* Restore the protection that unprotect() stored.
 */
static void
reprotect (uint8_t* p, size_t n, const DWORD protect[2])
{
  size_t m = first_page_size (p, n);
  DWORD o;

  VirtualProtect (p, m, protect[0], &o);

  if (m != n)
    VirtualProtect (p + m, n - m, protect[1], &o);
}

/* Write the hook's jump into the target function or restore the original
 * code. Return MH_ERROR_MEMORY_PROTECT if unable to make the code writable.
 *
 * Note that we ignore the failure to restore the protection since the code
 * is patched by then.
 */
static enum mh_status
patch_hook (unsigned int pos, bool enable)
{
  struct hook_entry* h = &hooks.items[pos];

  uint8_t* p = (uint8_t*) h->target;
  size_t n = sizeof (struct mh_jmp_rel);

  if (h->patch_above)
  {
    p -= sizeof (struct mh_jmp_rel);
    n += sizeof (struct mh_jmp_rel_short);
  }

  DWORD protect[2];
  if (!unprotect (p, n, protect))
    return MH_ERROR_MEMORY_PROTECT;

  if (enable)
  {
    struct mh_jmp_rel* j = (struct mh_jmp_rel*) p;
    j->opcode = 0xE9;
    j->operand = (uint32_t) ((uint8_t*) h->detour -
                             (p + sizeof (struct mh_jmp_rel)));

    /* Jump from the target to the long jump above it.
     */
    if (h->patch_above)
    {
      struct mh_jmp_rel_short* s = (struct mh_jmp_rel_short*) h->target;
      s->opcode = 0xEB;
      s->operand = (uint8_t) (0 - (sizeof (struct mh_jmp_rel_short) +
                                   sizeof (struct mh_jmp_rel)));
    }
  }
  else
    memcpy (p, h->backup, n);

  reprotect (p, n, protect);
  FlushInstructionCache (GetCurrentProcess (), p, n);

  h->enabled = enable;
  h->queue_enable = enable;

  return MH_OK;
}

/* Patch the hook with the process's other threads suspended.
 */
static enum mh_status
patch_hook_frozen (unsigned int pos, bool enable, enum action a)
{
  struct frozen_threads ts;
  enum mh_status r = freeze (&ts);

  if (r != MH_OK)
    return r;

  move_threads (&ts, pos, a);
  r = patch_hook (pos, enable);
  unfreeze (&ts);
  return r;
}

/* Apply the action to all the hooks with the process's other threads
 * suspended. Stop at the first hook that fails, leaving the earlier ones
 * changed.
 */
static enum mh_status
patch_hooks (enum action a)
{
  /* Find the first hook that the action changes. If there is none, then we
   * don't need to suspend the threads.
   */
  unsigned int first = INVALID_HOOK_POS;

  for (unsigned int i = 0; i < hooks.size; ++i)
  {
    if (hooks.items[i].enabled != target_state (&hooks.items[i], a))
    {
      first = i;
      break;
    }
  }

  if (first == INVALID_HOOK_POS)
    return MH_OK;

  struct frozen_threads ts;
  enum mh_status r = freeze (&ts);

  if (r != MH_OK)
    return r;

  move_threads (&ts, ALL_HOOKS_POS, a);

  for (unsigned int i = first; i < hooks.size; ++i)
  {
    bool enable = target_state (&hooks.items[i], a);

    if (hooks.items[i].enabled != enable)
    {
      r = patch_hook (i, enable);

      if (r != MH_OK)
        break;
    }
  }

  unfreeze (&ts);
  return r;
}

/* Acquire the API lock. InterlockedCompareExchange() is a full memory
 * barrier. While waiting, yield for a while and then sleep.
 */
static void
lock (void)
{
  for (size_t n = 0;
       InterlockedCompareExchange (&locked, TRUE, FALSE) != FALSE;
       ++n)
    Sleep (n < 32 ? 0 : 1);
}

/* Release the API lock. InterlockedExchange() is a full memory barrier.
 */
static void
unlock (void)
{
  InterlockedExchange (&locked, FALSE);
}

/* The API functions without the lock (see minhook.h for their semantics).
 */
static enum mh_status
initialize (void)
{
  if (heap != NULL)
    return MH_ERROR_ALREADY_INITIALIZED;

  heap = HeapCreate (0, 0, 0);

  if (heap == NULL)
    return MH_ERROR_MEMORY_ALLOC;

  mh_initialize_buffer ();
  return MH_OK;
}

static enum mh_status
uninitialize (void)
{
  if (heap == NULL)
    return MH_ERROR_NOT_INITIALIZED;

  /* Disable all the hooks first. If unable to, then stay initialized so
   * that the caller can try again.
   */
  enum mh_status r = patch_hooks (ACTION_DISABLE);

  if (r != MH_OK)
    return r;

  /* Destroying the heap frees the hook list. We free it explicitly as well
   * since some tools would otherwise report a leak.
   *
   * Note that we leave the hooks' trampolines allocated since a thread may
   * still enter them (see mh_uninitialize()).
   */
  HeapFree (heap, 0, hooks.items);
  HeapDestroy (heap);

  heap = NULL;

  hooks.items = NULL;
  hooks.capacity = 0;
  hooks.size = 0;

  return MH_OK;
}

/* Build the trampoline in the buffer and add the hook for the target.
 */
static enum mh_status
add_hook (void* target, void* detour, void* buffer, void** original)
{
  struct mh_trampoline t = {
    .target = target, .detour = detour, .trampoline = buffer};

  if (!mh_create_trampoline (&t))
    return MH_ERROR_UNSUPPORTED_FUNCTION;

  struct hook_entry* h = add_hook_entry ();

  if (h == NULL)
    return MH_ERROR_MEMORY_ALLOC;

  h->target = t.target;
#if defined(_M_X64) || defined(__x86_64__)
  h->detour = t.relay;
#else
  h->detour = t.detour;
#endif
  h->trampoline = t.trampoline;
  h->patch_above = t.patch_above;
  h->enabled = false;
  h->queue_enable = false;
  h->ip_count = t.ip_count;
  memcpy (h->old_ips, t.old_ips, sizeof (t.old_ips));
  memcpy (h->new_ips, t.new_ips, sizeof (t.new_ips));

  /* Back up the code that the hook overwrites.
   */
  if (t.patch_above)
    memcpy (h->backup,
            (uint8_t*) target - sizeof (struct mh_jmp_rel),
            sizeof (struct mh_jmp_rel) + sizeof (struct mh_jmp_rel_short));
  else
    memcpy (h->backup, target, sizeof (struct mh_jmp_rel));

  if (original != NULL)
    *original = h->trampoline;

  return MH_OK;
}

static enum mh_status
create_hook (void* target, void* detour, void** original)
{
  if (heap == NULL)
    return MH_ERROR_NOT_INITIALIZED;

  if (!mh_executable_address (target) || !mh_executable_address (detour))
    return MH_ERROR_NOT_EXECUTABLE;

  if (find_hook_entry (target) != INVALID_HOOK_POS)
    return MH_ERROR_ALREADY_CREATED;

  void* buffer = mh_allocate_buffer (target);

  if (buffer == NULL)
    return MH_ERROR_MEMORY_ALLOC;

  enum mh_status r = add_hook (target, detour, buffer, original);

  if (r != MH_OK)
    mh_free_buffer (buffer);

  return r;
}

static enum mh_status
remove_hook (void* target, mh_retirement_id* retired)
{
  if (heap == NULL)
    return MH_ERROR_NOT_INITIALIZED;

  unsigned int pos = find_hook_entry (target);

  if (pos == INVALID_HOOK_POS)
    return MH_ERROR_NOT_CREATED;

  /* Make room for the retirement first, so that we don't fail with the
   * hook already disabled.
   */
  if (retired != NULL && !reserve_retirement ())
    return MH_ERROR_MEMORY_ALLOC;

  if (hooks.items[pos].enabled)
  {
    enum mh_status r = patch_hook_frozen (pos, false, ACTION_DISABLE);

    if (r != MH_OK)
      return r;
  }

  /* Retire the trampoline. Without an id nobody can reclaim it, so we don't
   * record it.
   */
  if (retired != NULL)
  {
    struct retirement* r = &retirements.items[retirements.size++];
    r->id = next_retirement_id++;
    r->trampoline = hooks.items[pos].trampoline;

    *retired = r->id;
  }

  delete_hook_entry (pos);
  return MH_OK;
}

/* Return true if the suspended thread may be executing the trampoline or,
 * on x64, its relay, which is in the same slot. A thread that could not be
 * suspended (NULL) or whose context we can't read may be.
 */
static bool
executing (HANDLE thread, uintptr_t trampoline)
{
  if (thread == NULL)
    return true;

  CONTEXT c;
  c.ContextFlags = CONTEXT_CONTROL;

  if (!GetThreadContext (thread, &c))
    return true;

#if defined(_M_X64) || defined(__x86_64__)
  uintptr_t ip = (uintptr_t) c.Rip;
#else
  uintptr_t ip = (uintptr_t) c.Eip;
#endif

  return trampoline <= ip && ip < trampoline + MH_MEMORY_SLOT_SIZE;
}

/* Note that this function doesn't need the library initialized: the
 * retirements and the thread list come from the process heap and freeing a
 * trampoline only needs its block.
 */
static enum mh_status
reclaim (mh_retirement_id id)
{
  unsigned int pos = find_retirement (id);

  if (pos == INVALID_RETIREMENT_POS)
    return MH_ERROR_NOT_RETIRED;

  struct frozen_threads ts;
  enum mh_status r = freeze (&ts);

  if (r != MH_OK)
    return r;

  /* See if a thread executes the trampoline.
   */
  uintptr_t t = (uintptr_t) retirements.items[pos].trampoline;

  for (unsigned int i = 0; i < ts.size; ++i)
  {
    if (executing (ts.items[i], t))
    {
      r = MH_ERROR_BUSY;
      break;
    }
  }

  if (r == MH_OK)
  {
    mh_free_buffer ((void*) t);
    delete_retirement (pos);
  }

  unfreeze (&ts);
  return r;
}

/* Note that MinHook processes the threads for enabling in both cases. We
 * process them for the actual change since disabling restores the padding
 * under a thread that is suspended on the long jump in the hot patch area.
 */
static enum mh_status
enable_hook (void* target, bool enable)
{
  if (heap == NULL)
    return MH_ERROR_NOT_INITIALIZED;

  if (target == MH_ALL_HOOKS)
    return patch_hooks (enable ? ACTION_ENABLE : ACTION_DISABLE);

  unsigned int pos = find_hook_entry (target);

  if (pos == INVALID_HOOK_POS)
    return MH_ERROR_NOT_CREATED;

  if (hooks.items[pos].enabled == enable)
    return enable ? MH_ERROR_ENABLED : MH_ERROR_DISABLED;

  return patch_hook_frozen (pos,
                            enable,
                            enable ? ACTION_ENABLE : ACTION_DISABLE);
}

static enum mh_status
queue_hook (void* target, bool enable)
{
  if (heap == NULL)
    return MH_ERROR_NOT_INITIALIZED;

  if (target == MH_ALL_HOOKS)
  {
    for (unsigned int i = 0; i < hooks.size; ++i)
      hooks.items[i].queue_enable = enable;

    return MH_OK;
  }

  unsigned int pos = find_hook_entry (target);

  if (pos == INVALID_HOOK_POS)
    return MH_ERROR_NOT_CREATED;

  hooks.items[pos].queue_enable = enable;
  return MH_OK;
}

static enum mh_status
apply_queued (void)
{
  if (heap == NULL)
    return MH_ERROR_NOT_INITIALIZED;

  return patch_hooks (ACTION_APPLY_QUEUED);
}

enum mh_status
mh_initialize (void)
{
  lock ();
  enum mh_status r = initialize ();
  unlock ();
  return r;
}

enum mh_status
mh_uninitialize (void)
{
  lock ();
  enum mh_status r = uninitialize ();
  unlock ();
  return r;
}

enum mh_status
mh_create_hook (void* target, void* detour, void** original)
{
  lock ();
  enum mh_status r = create_hook (target, detour, original);
  unlock ();
  return r;
}

enum mh_status
mh_remove_hook (void* target, mh_retirement_id* retired)
{
  lock ();
  enum mh_status r = remove_hook (target, retired);
  unlock ();
  return r;
}

enum mh_status
mh_reclaim (mh_retirement_id id)
{
  lock ();
  enum mh_status r = reclaim (id);
  unlock ();
  return r;
}

enum mh_status
mh_enable_hook (void* target)
{
  lock ();
  enum mh_status r = enable_hook (target, true);
  unlock ();
  return r;
}

enum mh_status
mh_disable_hook (void* target)
{
  lock ();
  enum mh_status r = enable_hook (target, false);
  unlock ();
  return r;
}

enum mh_status
mh_queue_enable_hook (void* target)
{
  lock ();
  enum mh_status r = queue_hook (target, true);
  unlock ();
  return r;
}

enum mh_status
mh_queue_disable_hook (void* target)
{
  lock ();
  enum mh_status r = queue_hook (target, false);
  unlock ();
  return r;
}

enum mh_status
mh_apply_queued (void)
{
  lock ();
  enum mh_status r = apply_queued ();
  unlock ();
  return r;
}

enum mh_status
mh_create_hook_api_ex (const wchar_t* module,
                       const char* function,
                       void* detour,
                       void** original,
                       void** target)
{
  HMODULE m = GetModuleHandleW (module);

  if (m == NULL)
    return MH_ERROR_MODULE_NOT_FOUND;

  FARPROC f = GetProcAddress (m, function);

  if (f == NULL)
    return MH_ERROR_FUNCTION_NOT_FOUND;

  /* ISO C has no conversion between function and object pointers, so we
   * copy the representation (they are the same on Windows).
   */
  void* t;
  memcpy (&t, &f, sizeof (t));

  if (target != NULL)
    *target = t;

  return mh_create_hook (t, detour, original);
}

enum mh_status
mh_create_hook_api (const wchar_t* module,
                    const char* function,
                    void* detour,
                    void** original)
{
  return mh_create_hook_api_ex (module, function, detour, original, NULL);
}

const char*
mh_status_to_string (enum mh_status s)
{
  switch (s)
  {
    case MH_UNKNOWN:                    return "MH_UNKNOWN";
    case MH_OK:                         return "MH_OK";
    case MH_ERROR_ALREADY_INITIALIZED:  return "MH_ERROR_ALREADY_INITIALIZED";
    case MH_ERROR_NOT_INITIALIZED:      return "MH_ERROR_NOT_INITIALIZED";
    case MH_ERROR_ALREADY_CREATED:      return "MH_ERROR_ALREADY_CREATED";
    case MH_ERROR_NOT_CREATED:          return "MH_ERROR_NOT_CREATED";
    case MH_ERROR_ENABLED:              return "MH_ERROR_ENABLED";
    case MH_ERROR_DISABLED:             return "MH_ERROR_DISABLED";
    case MH_ERROR_NOT_EXECUTABLE:       return "MH_ERROR_NOT_EXECUTABLE";
    case MH_ERROR_UNSUPPORTED_FUNCTION: return "MH_ERROR_UNSUPPORTED_FUNCTION";
    case MH_ERROR_MEMORY_ALLOC:         return "MH_ERROR_MEMORY_ALLOC";
    case MH_ERROR_MEMORY_PROTECT:       return "MH_ERROR_MEMORY_PROTECT";
    case MH_ERROR_MODULE_NOT_FOUND:     return "MH_ERROR_MODULE_NOT_FOUND";
    case MH_ERROR_FUNCTION_NOT_FOUND:   return "MH_ERROR_FUNCTION_NOT_FOUND";
    case MH_ERROR_BUSY:                 return "MH_ERROR_BUSY";
    case MH_ERROR_NOT_RETIRED:          return "MH_ERROR_NOT_RETIRED";
  }

  return "(unknown)";
}
