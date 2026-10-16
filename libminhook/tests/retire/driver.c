#include <stdio.h>
#include <stdint.h>
#include <string.h>  /* strcmp(), memcpy() */
#include <stdbool.h>

#include <libminhook/minhook.h>

#include <common/code.h>

/* Usage: argv[0] <scenario>
 *
 * Remove hooks, reclaim their trampolines, and print the outcome of each
 * step on a line of its own: the status name for an API call, the result
 * for a call to a function, the retirement id, and whether the trampoline's
 * memory is allocated (1) or not (0). The scenarios are:
 *
 * reclaim        remove a hook and reclaim its trampoline twice
 * repeat         hook and remove the same target twice and reclaim the
 *                first trampoline and then the second
 * unknown        reclaim ids that were never issued
 * null           remove a hook without a retirement id
 * uninitialize   uninitialize with a hook and call its trampoline
 * uninitialized  remove a hook, uninitialize, and reclaim its trampoline
 * call           remove a hook while another thread is inside a call that
 *                its trampoline made
 * busy           reclaim a trampoline while another thread runs a loop
 *                within it
 *
 * The target function is mov eax, 42; ret (except in call and busy) and its
 * detour adds 1000 to the result of the original function.
 */

#define COUNT(a) (sizeof (a) / sizeof ((a)[0]))

/* Offsets of the target function and of the code that it uses in the page.
 */
#define TARGET_OFFSET 0x10
#define STUB_OFFSET   0x40
#define PARK_OFFSET   0x100

typedef int target_function (void);

/* Trampoline of the most recently created hook as a data and a function
 * pointer.
 */
static void*            tramp;
static target_function* original;

static int
detour (void)
{
  return original () + 1000;
}

static void*
detour_address (void)
{
  target_function* f = &detour;
  void* r;
  memcpy (&r, &f, sizeof (r));
  return r;
}

static int
call (void* p)
{
  target_function* f;
  memcpy (&f, &p, sizeof (f));
  return f ();
}

static void
print_status (const char* step, enum mh_status s)
{
  printf ("%s %s\n", step, mh_status_to_string (s));
}

/* Print whether the memory at the address is allocated.
 */
static void
print_allocated (const void* p)
{
  MEMORY_BASIC_INFORMATION i;
  SIZE_T n = VirtualQuery (p, &i, sizeof (i));
  assert (n != 0);

  printf ("allocated %d\n", i.State == MEM_COMMIT ? 1 : 0);
}

static const uint8_t function_code[] = {0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3};

/* Allocate the page with the function as the target.
 */
static uint8_t*
allocate_function (void)
{
  return code_allocate (TARGET_OFFSET, function_code, sizeof (function_code));
}

static enum mh_status
create (uint8_t* p)
{
  enum mh_status r = mh_create_hook (p + TARGET_OFFSET,
                                     detour_address (),
                                     &tramp);

  memcpy (&original, &tramp, sizeof (original));
  return r;
}

static void
reclaim (void)
{
  uint8_t* p = allocate_function ();
  mh_retirement_id id = 0;

  print_status ("initialize", mh_initialize ());
  print_status ("create", create (p));
  print_status ("enable", mh_enable_hook (p + TARGET_OFFSET));
  print_status ("remove", mh_remove_hook (p + TARGET_OFFSET, &id));
  printf ("id %llu\n", (unsigned long long) id);
  printf ("call %d\n", call (p + TARGET_OFFSET));
  print_allocated (tramp);
  print_status ("reclaim", mh_reclaim_trampoline (id));
  print_allocated (tramp);
  print_status ("reclaim", mh_reclaim_trampoline (id));
  print_status ("uninitialize", mh_uninitialize ());

  code_free (p);
}

static void
repeat (void)
{
  uint8_t* p = allocate_function ();
  mh_retirement_id ids[2];
  void* trampolines[2];

  print_status ("initialize", mh_initialize ());

  for (size_t i = 0; i != COUNT (ids); ++i)
  {
    print_status ("create", create (p));
    trampolines[i] = tramp;
    print_status ("remove", mh_remove_hook (p + TARGET_OFFSET, &ids[i]));
    printf ("id %llu\n", (unsigned long long) ids[i]);
  }

  print_status ("reclaim", mh_reclaim_trampoline (ids[0]));
  print_status ("reclaim", mh_reclaim_trampoline (ids[1]));
  print_allocated (trampolines[0]);
  print_allocated (trampolines[1]);
  print_status ("uninitialize", mh_uninitialize ());

  code_free (p);
}

static void
unknown (void)
{
  print_status ("reclaim", mh_reclaim_trampoline (0));
  print_status ("reclaim", mh_reclaim_trampoline (1));
}

static void
null (void)
{
  uint8_t* p = allocate_function ();

  print_status ("initialize", mh_initialize ());
  print_status ("create", create (p));
  print_status ("remove", mh_remove_hook (p + TARGET_OFFSET, NULL));
  printf ("original %d\n", original ());
  print_allocated (tramp);
  print_status ("uninitialize", mh_uninitialize ());

  code_free (p);
}

static void
uninitialize (void)
{
  uint8_t* p = allocate_function ();

  print_status ("initialize", mh_initialize ());
  print_status ("create", create (p));
  print_status ("enable", mh_enable_hook (p + TARGET_OFFSET));
  print_status ("uninitialize", mh_uninitialize ());
  printf ("call %d\n", call (p + TARGET_OFFSET));
  printf ("original %d\n", original ());
  print_allocated (tramp);

  code_free (p);
}

static void
uninitialized (void)
{
  uint8_t* p = allocate_function ();
  mh_retirement_id id = 0;

  print_status ("initialize", mh_initialize ());
  print_status ("create", create (p));
  print_status ("remove", mh_remove_hook (p + TARGET_OFFSET, &id));
  print_status ("uninitialize", mh_uninitialize ());
  print_status ("reclaim", mh_reclaim_trampoline (id));
  print_allocated (tramp);

  code_free (p);
}

/* Events of the target's callee, which signals entered and waits until
 * released is signaled.
 */
static HANDLE entered;
static HANDLE released;

static int
callee (void)
{
  SetEvent (entered);
  WaitForSingleObject (released, INFINITE);
  return 7;
}

static DWORD WINAPI
run_target (void* p)
{
  return (DWORD) call ((uint8_t*) p + TARGET_OFFSET);
}

/* The target is call <stub>; ret and the stub jumps to the callee, which
 * may be out of the reach of a relative call on x64. The trampoline makes
 * the call, so the other thread waits in the callee with a return address
 * into the trampoline while we remove the hook.
 */
static void
call_retired (void)
{
  const uint8_t c[] = {0xE8, 0x2B, 0x00, 0x00, 0x00, 0xC3};
  uint8_t* p = code_allocate (TARGET_OFFSET, c, sizeof (c));

  /* mov eax/rax, <callee>; jmp eax/rax
   */
  {
    target_function* f = &callee;
    uintptr_t a;
    memcpy (&a, &f, sizeof (a));

    uint8_t* s = p + STUB_OFFSET;
#if defined(_M_X64) || defined(__x86_64__)
    *s++ = 0x48;
#endif
    *s++ = 0xB8;
    memcpy (s, &a, sizeof (a));
    s += sizeof (a);
    *s++ = 0xFF;
    *s++ = 0xE0;
  }

  entered = CreateEventW (NULL, TRUE, FALSE, NULL);
  released = CreateEventW (NULL, TRUE, FALSE, NULL);
  assert (entered != NULL && released != NULL);

  mh_retirement_id id = 0;

  print_status ("initialize", mh_initialize ());
  print_status ("create", create (p));
  print_status ("enable", mh_enable_hook (p + TARGET_OFFSET));

  HANDLE t = CreateThread (NULL, 0, &run_target, p, 0, NULL);
  assert (t != NULL);
  WaitForSingleObject (entered, INFINITE);

  print_status ("remove", mh_remove_hook (p + TARGET_OFFSET, &id));

  SetEvent (released);
  WaitForSingleObject (t, INFINITE);

  DWORD r;
  BOOL b = GetExitCodeThread (t, &r);
  assert (b);
  printf ("call %d\n", (int) r);

  CloseHandle (t);
  print_status ("reclaim", mh_reclaim_trampoline (id));
  print_status ("uninitialize", mh_uninitialize ());

  CloseHandle (released);
  CloseHandle (entered);
  code_free (p);
}

/* The loop that the other thread runs: pause, then jump back to it.
 */
static const uint8_t spin_loop[] = {0xF3, 0x90, 0xEB, 0xFC};

/* Return the thread's instruction pointer.
 */
static uintptr_t
thread_ip (HANDLE t)
{
  CONTEXT c;
  c.ContextFlags = CONTEXT_CONTROL;

  BOOL r = GetThreadContext (t, &c);
  assert (r);

#if defined(_M_X64) || defined(__x86_64__)
  return (uintptr_t) c.Rip;
#else
  return (uintptr_t) c.Eip;
#endif
}

static void
set_thread_ip (HANDLE t, uintptr_t ip)
{
  CONTEXT c;
  c.ContextFlags = CONTEXT_CONTROL;

  BOOL r = GetThreadContext (t, &c);
  assert (r);

#if defined(_M_X64) || defined(__x86_64__)
  c.Rip = ip;
#else
  c.Eip = (DWORD) ip;
#endif

  r = SetThreadContext (t, &c);
  assert (r);
}

/* The target is the loop followed by nop and ret, so the trampoline holds
 * the loop. The other thread runs the loop in the trampoline of the
 * disabled hook, which removing the hook leaves alone. We then move it,
 * suspended, to the same loop elsewhere in the page.
 */
static void
busy (void)
{
  const uint8_t c[] = {0xF3, 0x90, 0xEB, 0xFC, 0x90, 0xC3};
  uint8_t* p = code_allocate (TARGET_OFFSET, c, sizeof (c));
  memcpy (p + PARK_OFFSET, spin_loop, sizeof (spin_loop));

  mh_retirement_id id = 0;
  print_status ("initialize", mh_initialize ());
  print_status ("create",
                mh_create_hook (p + TARGET_OFFSET, p + PARK_OFFSET, &tramp));

  LPTHREAD_START_ROUTINE s;
  memcpy (&s, &tramp, sizeof (s));

  HANDLE t = CreateThread (NULL, 0, s, NULL, 0, NULL);
  assert (t != NULL);

  /* Wait until the thread runs the loop.
   */
  for (;;)
  {
    SuspendThread (t);
    uintptr_t ip = thread_ip (t);
    ResumeThread (t);

    if (ip == (uintptr_t) tramp || ip == (uintptr_t) tramp + 2)
      break;

    Sleep (1);
  }

  print_status ("remove", mh_remove_hook (p + TARGET_OFFSET, &id));
  print_status ("reclaim", mh_reclaim_trampoline (id));
  print_allocated (tramp);

  SuspendThread (t);
  set_thread_ip (t, (uintptr_t) p + PARK_OFFSET);
  ResumeThread (t);

  print_status ("reclaim", mh_reclaim_trampoline (id));
  print_allocated (tramp);

  BOOL r = TerminateThread (t, 0);
  assert (r);
  WaitForSingleObject (t, INFINITE);
  CloseHandle (t);

  print_status ("uninitialize", mh_uninitialize ());
  code_free (p);
}

struct scenario
{
  const char* name;
  void      (*function) (void);
};

static const struct scenario scenarios[] = {
  {"reclaim",       &reclaim},
  {"repeat",        &repeat},
  {"unknown",       &unknown},
  {"null",          &null},
  {"uninitialize",  &uninitialize},
  {"uninitialized", &uninitialized},
  {"call",          &call_retired},
  {"busy",          &busy}};

int
main (int argc, char* argv[])
{
  if (argc != 2)
  {
    fprintf (stderr, "error: expected scenario\n");
    return 1;
  }

  for (size_t i = 0; i != COUNT (scenarios); ++i)
  {
    if (strcmp (argv[1], scenarios[i].name) == 0)
    {
      scenarios[i].function ();
      return 0;
    }
  }

  fprintf (stderr, "error: invalid scenario '%s'\n", argv[1]);
  return 1;
}
