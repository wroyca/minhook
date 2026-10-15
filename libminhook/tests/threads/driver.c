#include <stdio.h>
#include <stdint.h>
#include <string.h>  /* strcmp(), memcpy() */
#include <stdbool.h>

#include <libminhook/minhook.h>

#include <common/code.h>

/* Usage: argv[0] <scenario>
 *
 * Run the scenario with other threads in the process and print the outcome
 * of each step on a line of its own. The scenarios are:
 *
 * spin        toggle the hook of a function that another thread runs
 * inside      enable and disable the hook while another thread runs a loop
 *             within the code that the hook overwrites
 * relay       remove the hook while another thread is at the x64 relay
 * hot-patch   disable and remove the hook while another thread is at the
 *             long jump in the hot patch area
 * many        toggle a hook with more threads than the initial capacity of
 *             the library's thread list
 * concurrent  toggle two hooks from two threads at once
 *
 * The inside, relay, and hot-patch scenarios also print where the other
 * thread is after each state change: target (within the code that the hook
 * overwrites), trampoline, or elsewhere.
 */

#define COUNT(a) (sizeof (a) / sizeof ((a)[0]))

/* Calls to a target function must go through its code, which the hook
 * patches, so we can't let the compiler inline them.
 */
#ifdef _MSC_VER
#  define LIBMINHOOK_NOINLINE __declspec(noinline)
#else
#  define LIBMINHOOK_NOINLINE __attribute__((noinline))
#endif

typedef int target_function (int);

/* ISO C has no conversion between function and object pointers, so we
 * copy the representation (they are the same on Windows).
 */
static void*
address (target_function* f)
{
  void* r;
  memcpy (&r, &f, sizeof (r));
  return r;
}

static LPTHREAD_START_ROUTINE
start_routine (const void* p)
{
  LPTHREAD_START_ROUTINE r;
  memcpy (&r, &p, sizeof (r));
  return r;
}

static void
print_status (const char* step, enum mh_status s)
{
  printf ("%s %s\n", step, mh_status_to_string (s));
}

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

/* Print where the suspended thread is relative to the target and its
 * trampoline (see the usage above).
 */
static void
print_location (const char* step, HANDLE t, uint8_t* target, void* tramp)
{
  uintptr_t ip = thread_ip (t);
  uintptr_t ta = (uintptr_t) target;
  uintptr_t tr = (uintptr_t) tramp;

  const char* l = ta <= ip && ip < ta + 5  ? "target"     :
                  tr <= ip && ip < tr + 64 ? "trampoline" :
                                             "elsewhere";

  printf ("%s %s\n", step, l);
}

/* The loop that the other threads run: pause, then jump back to it.
 */
static const uint8_t spin_loop[] = {0xF3, 0x90, 0xEB, 0xFC};

/* Start a thread at the code and wait until it runs the first instruction
 * of its loop or the one after it.
 */
static HANDLE
start_spinning (uint8_t* code)
{
  HANDLE t = CreateThread (NULL, 0, start_routine (code), NULL, 0, NULL);
  assert (t != NULL);

  for (;;)
  {
    SuspendThread (t);
    uintptr_t ip = thread_ip (t);
    ResumeThread (t);

    if (ip == (uintptr_t) code || ip == (uintptr_t) code + 2)
      break;

    Sleep (1);
  }

  return t;
}

static void
stop_spinning (HANDLE t)
{
  BOOL r = TerminateThread (t, 0);
  assert (r);

  WaitForSingleObject (t, INFINITE);
  CloseHandle (t);
}

static volatile LONG stop;

LIBMINHOOK_NOINLINE static int
target_spin (int x)
{
  volatile int r = x;
  while (InterlockedCompareExchange (&stop, 0, 0) == 0)
    r = r + 1;
  return r;
}

static int
detour_spin (int x)
{
  return x;
}

static DWORD WINAPI
run_spin (void* p)
{
  (void) p;
  return (DWORD) target_spin (0);
}

static void
spin (void)
{
  print_status ("initialize", mh_initialize ());

  target_function* o;
  print_status ("create",
                mh_create_hook (address (&target_spin),
                                address (&detour_spin),
                                (void**) &o));

  stop = 0;
  HANDLE t = CreateThread (NULL, 0, &run_spin, NULL, 0, NULL);
  assert (t != NULL);
  Sleep (50);

  /* Each change suspends the thread and moves it out of the code that it
   * patches.
   */
  bool r = true;
  for (size_t i = 0; i != 100; ++i)
  {
    r = r && mh_enable_hook (address (&target_spin)) == MH_OK;
    r = r && mh_disable_hook (address (&target_spin)) == MH_OK;
  }

  InterlockedExchange (&stop, 1);
  WaitForSingleObject (t, INFINITE);
  CloseHandle (t);

  printf ("toggle %d\n", r ? 1 : 0);
  print_status ("uninitialize", mh_uninitialize ());
}

/* The target is the loop followed by nop and ret, so that the loop is
 * within the code that the hook overwrites. The detour is a loop of its own
 * that the scenarios never run. The other target is mov eax, 1; ret.
 */
#define TARGET_OFFSET 0x10
#define DETOUR_OFFSET 0x100
#define OTHER_OFFSET  0x200

static uint8_t*
allocate_loops (void)
{
  const uint8_t c[] = {0xF3, 0x90, 0xEB, 0xFC, 0x90, 0xC3};

  uint8_t* p = code_allocate (TARGET_OFFSET, c, sizeof (c));
  memcpy (p + DETOUR_OFFSET, spin_loop, sizeof (spin_loop));
  return p;
}

/* Run the state change and print its status and where the other thread
 * is afterwards.
 */
static void
step (const char* name,
      enum mh_status s,
      HANDLE t,
      uint8_t* target,
      void* tramp)
{
  print_status (name, s);

  SuspendThread (t);
  print_location (name, t, target, tramp);
  ResumeThread (t);
}

static void
inside (void)
{
  uint8_t* p = allocate_loops ();
  uint8_t* target = p + TARGET_OFFSET;
  void* tramp;

  const uint8_t o[] = {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3};
  memcpy (p + OTHER_OFFSET, o, sizeof (o));

  print_status ("initialize", mh_initialize ());
  print_status ("create", mh_create_hook (target, p + DETOUR_OFFSET, &tramp));

  /* Create and enable another hook. Applying the target's queued changes
   * leaves it as is.
   */
  print_status ("create-other",
                mh_create_hook (p + OTHER_OFFSET, p + DETOUR_OFFSET, NULL));
  print_status ("enable-other", mh_enable_hook (p + OTHER_OFFSET));

  HANDLE t = start_spinning (target);

  step ("enable",        mh_enable_hook (target),        t, target, tramp);
  step ("disable",       mh_disable_hook (target),       t, target, tramp);
  step ("enable",        mh_enable_hook (target),        t, target, tramp);
  step ("disable-all",   mh_disable_hook (MH_ALL_HOOKS), t, target, tramp);
  step ("enable-all",    mh_enable_hook (MH_ALL_HOOKS),  t, target, tramp);
  step ("queue-disable", mh_queue_disable_hook (target), t, target, tramp);
  step ("apply",         mh_apply_queued (),             t, target, tramp);
  step ("queue-enable",  mh_queue_enable_hook (target),  t, target, tramp);
  step ("apply",         mh_apply_queued (),             t, target, tramp);
  step ("remove",        mh_remove_hook (target),        t, target, tramp);

  stop_spinning (t);
  print_status ("uninitialize", mh_uninitialize ());
  code_free (p);
}

/* Return the destination of the relative jump that the enabled hook wrote
 * at the address.
 */
static uintptr_t
jump_destination (const uint8_t* p)
{
  assert (p[0] == 0xE9);

  int32_t d;
  memcpy (&d, p + 1, sizeof (d));
  return (uintptr_t) p + 5 + (uintptr_t) (intptr_t) d;
}

/* The other thread spins in the detour's loop and we place it, suspended,
 * at the relay. Removing the hook then moves it to the target.
 */
static void
relay (void)
{
  uint8_t* p = allocate_loops ();
  uint8_t* target = p + TARGET_OFFSET;
  void* tramp;

  print_status ("initialize", mh_initialize ());
  print_status ("create", mh_create_hook (target, p + DETOUR_OFFSET, &tramp));
  print_status ("enable", mh_enable_hook (target));

  HANDLE t = start_spinning (p + DETOUR_OFFSET);

  SuspendThread (t);
  set_thread_ip (t, jump_destination (target));

  print_status ("remove", mh_remove_hook (target));
  print_location ("remove", t, target, tramp);
  ResumeThread (t);

  stop_spinning (t);
  print_status ("uninitialize", mh_uninitialize ());
  code_free (p);
}

/* The target is a short jump to a ret, followed by code that is not
 * padding, so the hook overwrites it with a short jump to a long one in the
 * padding above it. The other thread spins elsewhere and we place it,
 * suspended, at the long jump. Disabling the hook then moves it to the
 * target, and so does removing the hook.
 */
static void
hot_patch (void)
{
  const uint8_t c[] = {0xEB, 0x03, 0x31, 0xC0, 0xC3, 0xC3};

  uint8_t* p = code_allocate (TARGET_OFFSET, c, sizeof (c));
  uint8_t* target = p + TARGET_OFFSET;
  void* tramp;

  memcpy (p + DETOUR_OFFSET, spin_loop, sizeof (spin_loop));

  print_status ("initialize", mh_initialize ());
  print_status ("create", mh_create_hook (target, p + DETOUR_OFFSET, &tramp));
  print_status ("enable", mh_enable_hook (target));

  HANDLE t = start_spinning (p + DETOUR_OFFSET);

  /* Disabling all the hooks looks the thread up in the hot patch area
   * first, where it isn't.
   */
  step ("disable-all",   mh_disable_hook (MH_ALL_HOOKS), t, target, tramp);
  step ("enable",        mh_enable_hook (target),        t, target, tramp);

  /* Return the thread to its loop before resuming it since the target
   * would return from the thread.
   */
  SuspendThread (t);
  set_thread_ip (t, (uintptr_t) target - 5);

  print_status ("disable", mh_disable_hook (target));
  print_location ("disable", t, target, tramp);

  set_thread_ip (t, (uintptr_t) p + DETOUR_OFFSET);
  ResumeThread (t);

  print_status ("enable", mh_enable_hook (target));

  SuspendThread (t);
  set_thread_ip (t, (uintptr_t) target - 5);

  print_status ("remove", mh_remove_hook (target));
  print_location ("remove", t, target, tramp);
  ResumeThread (t);

  stop_spinning (t);
  print_status ("uninitialize", mh_uninitialize ());
  code_free (p);
}

static DWORD WINAPI
wait_event (void* e)
{
  WaitForSingleObject ((HANDLE) e, INFINITE);
  return 0;
}

LIBMINHOOK_NOINLINE static int
target_twice (int x)
{
  volatile int r = x * 2;
  return r;
}

static target_function* original_twice;

static int
detour_twice (int x)
{
  return original_twice (x) + 1000;
}

/* Note that the library's thread list starts with room for 128 threads and
 * that disabling all the hooks looks up each thread in all of them.
 */
static void
many (void)
{
  HANDLE e = CreateEventW (NULL, TRUE, FALSE, NULL);
  assert (e != NULL);

  HANDLE ts[200];
  for (size_t i = 0; i != COUNT (ts); ++i)
  {
    ts[i] = CreateThread (NULL, 0, &wait_event, e, 0, NULL);
    assert (ts[i] != NULL);
  }

  print_status ("initialize", mh_initialize ());
  print_status ("create",
                mh_create_hook (address (&target_twice),
                                address (&detour_twice),
                                (void**) &original_twice));
  print_status ("enable", mh_enable_hook (address (&target_twice)));
  printf ("call %d\n", target_twice (5));
  print_status ("disable", mh_disable_hook (address (&target_twice)));
  printf ("call %d\n", target_twice (5));
  print_status ("enable", mh_enable_hook (address (&target_twice)));
  print_status ("disable-all", mh_disable_hook (MH_ALL_HOOKS));
  printf ("call %d\n", target_twice (5));
  print_status ("uninitialize", mh_uninitialize ());

  SetEvent (e);

  for (size_t i = 0; i != COUNT (ts); ++i)
  {
    WaitForSingleObject (ts[i], INFINITE);
    CloseHandle (ts[i]);
  }

  CloseHandle (e);
}

LIBMINHOOK_NOINLINE static int
target_thrice (int x)
{
  volatile int r = x * 3;
  return r;
}

static target_function* original_thrice;

static int
detour_thrice (int x)
{
  return original_thrice (x) + 2000;
}

/* Toggle the hook of the target function many times and return whether
 * every change succeeded.
 */
static DWORD WINAPI
toggle (void* f)
{
  bool r = true;

  for (size_t i = 0; i != 200; ++i)
  {
    r = r && mh_enable_hook (f) == MH_OK;
    r = r && mh_disable_hook (f) == MH_OK;
  }

  return r ? 1 : 0;
}

static void
concurrent (void)
{
  void* fs[] = {address (&target_twice), address (&target_thrice)};

  print_status ("initialize", mh_initialize ());
  print_status ("create-twice",
                mh_create_hook (fs[0],
                                address (&detour_twice),
                                (void**) &original_twice));
  print_status ("create-thrice",
                mh_create_hook (fs[1],
                                address (&detour_thrice),
                                (void**) &original_thrice));

  HANDLE ts[COUNT (fs)];
  for (size_t i = 0; i != COUNT (fs); ++i)
  {
    ts[i] = CreateThread (NULL, 0, &toggle, fs[i], 0, NULL);
    assert (ts[i] != NULL);
  }

  bool r = true;
  for (size_t i = 0; i != COUNT (ts); ++i)
  {
    DWORD c;
    WaitForSingleObject (ts[i], INFINITE);
    GetExitCodeThread (ts[i], &c);
    CloseHandle (ts[i]);

    r = r && c == 1;
  }

  printf ("toggle %d\n", r ? 1 : 0);
  printf ("call %d %d\n", target_twice (5), target_thrice (5));
  print_status ("uninitialize", mh_uninitialize ());
}

struct scenario
{
  const char* name;
  void      (*function) (void);
};

static const struct scenario scenarios[] = {
  {"spin",       &spin},
  {"inside",     &inside},
  {"relay",      &relay},
  {"hot-patch",  &hot_patch},
  {"many",       &many},
  {"concurrent", &concurrent}};

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
