#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>  /* strcmp(), memcpy() */
#include <stdbool.h>

#include <libminhook/minhook.h>

#include <common/code.h>
#include <common/fault.h>

/* Usage: argv[0] <scenario>
 *
 * Make the Win32 functions that the library calls fail at a point that the
 * scenario chooses and print the outcome of each step on a line of its own:
 * the status name for an API call and the returned value for a call to a
 * function. The scenarios are:
 *
 * heap-create         HeapCreate() when initializing
 * hook-alloc          HeapAlloc() when creating the first hook
 * hook-grow           HeapReAlloc() when growing the hook list
 * hook-shrink         HeapReAlloc() when shrinking the hook list
 * thread-alloc        HeapAlloc() when collecting the threads
 * thread-grow         HeapReAlloc() when growing the thread list
 * next-thread-first   NtGetNextThread() for the first thread when enabling
 *                     one hook and all of them
 * next-thread         NtGetNextThread() for a later thread when enabling
 * suspend-thread      SuspendThread() when enabling
 * thread-context      GetThreadContext() when enabling
 * protect-enable      VirtualProtect() when enabling one hook
 * protect-all         VirtualProtect() when enabling all the hooks
 * protect-remove      VirtualProtect() when removing an enabled hook
 * protect-uninitialize
 *                     VirtualProtect() when uninitializing with an enabled
 *                     hook
 * virtual-alloc       VirtualAlloc() when allocating a trampoline block
 *
 * After enabling, the scenarios that enable a single hook also print the
 * number of the thread handles that the library has not closed.
 *
 * The functions a and b return x * 3 + 1 and (x ^ 0x55) - 7, respectively,
 * and their detours add 1000 and 2000 to the result of the original
 * function.
 *
 * See common/fault.h for how we make the functions fail.
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

/* Target functions. The volatile arithmetic keeps each of them long enough
 * to hook.
 */
LIBMINHOOK_NOINLINE static int
target_a (int x)
{
  volatile int r = x * 3;
  return r + 1;
}

LIBMINHOOK_NOINLINE static int
target_b (int x)
{
  volatile int r = x ^ 0x55;
  return r - 7;
}

typedef int target_function (int);

static target_function* original_a;
static target_function* original_b;

static int
detour_a (int x)
{
  return original_a (x) + 1000;
}

static int
detour_b (int x)
{
  return original_b (x) + 2000;
}

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

static void
print_status (const char* step, enum mh_status s)
{
  printf ("%s %s\n", step, mh_status_to_string (s));
}

static void
print_result (const char* step, int r)
{
  printf ("%s %d\n", step, r);
}

static void
print_handles (void)
{
  printf ("handles %ld\n", fault_thread_handles);
}

static enum mh_status
create_a (void)
{
  return mh_create_hook (address (&target_a),
                         address (&detour_a),
                         (void**) &original_a);
}

static enum mh_status
create_b (void)
{
  return mh_create_hook (address (&target_b),
                         address (&detour_b),
                         (void**) &original_b);
}

/* Threads that wait until they are stopped, so that enabling a hook has
 * threads other than the current one to process.
 */
static HANDLE stop_event;
static HANDLE waiting[200];
static size_t waiting_count;

static DWORD WINAPI
wait_stop (void* p)
{
  (void) p;
  WaitForSingleObject (stop_event, INFINITE);
  return 0;
}

static void
start_threads (size_t n)
{
  assert (n <= COUNT (waiting));

  stop_event = CreateEventW (NULL, TRUE, FALSE, NULL);
  assert (stop_event != NULL);

  for (waiting_count = 0; waiting_count != n; ++waiting_count)
  {
    HANDLE t = CreateThread (NULL, 0, &wait_stop, NULL, 0, NULL);
    assert (t != NULL);
    waiting[waiting_count] = t;
  }
}

static void
stop_threads (void)
{
  SetEvent (stop_event);

  for (size_t i = 0; i != waiting_count; ++i)
  {
    WaitForSingleObject (waiting[i], INFINITE);
    CloseHandle (waiting[i]);
  }

  CloseHandle (stop_event);
  waiting_count = 0;
}

/* Generated functions, the function i being mov eax, i; ret, and their
 * detour, which returns -1.
 */
#define GENERATED_SIZE 16

static uint8_t* generated;

static void
generate (size_t n)
{
  assert (n * GENERATED_SIZE <= CODE_PAGE_SIZE);

  generated = code_allocate (0, NULL, 0);

  for (size_t i = 0; i != n; ++i)
  {
    const uint32_t v = (uint32_t) i;
    uint8_t* f = generated + i * GENERATED_SIZE;

    f[0] = 0xB8;
    memcpy (f + 1, &v, sizeof (v));
    f[5] = 0xC3;
  }
}

static int
detour_generated (void)
{
  return -1;
}

static enum mh_status
create_generated (size_t i)
{
  int (*d) (void) = &detour_generated;
  void* da;
  memcpy (&da, &d, sizeof (da));

  return mh_create_hook (generated + i * GENERATED_SIZE, da, NULL);
}

/* Return the number of the generated functions in the range for which
 * the operation succeeds.
 */
static size_t
count_ok (size_t b, size_t e, enum mh_status (*f) (size_t))
{
  size_t r = 0;

  for (size_t i = b; i != e; ++i)
  {
    if (f (i) == MH_OK)
      ++r;
  }

  return r;
}

static enum mh_status
remove_generated (size_t i)
{
  return mh_remove_hook (generated + i * GENERATED_SIZE);
}

static void
heap_create (void)
{
  fault_next (FAULT_HEAP_CREATE, 1);
  print_status ("initialize", mh_initialize ());
  print_status ("initialize", mh_initialize ());
  print_status ("uninitialize", mh_uninitialize ());
}

static void
hook_alloc (void)
{
  print_status ("initialize", mh_initialize ());
  fault_next (FAULT_HEAP_ALLOC, 1);
  print_status ("create", create_a ());
  print_status ("create", create_a ());
  print_status ("enable", mh_enable_hook (address (&target_a)));
  print_result ("call", target_a (5));
  print_status ("uninitialize", mh_uninitialize ());
}

/* Note that the hook list starts with room for 32 hooks, doubles when
 * full, and halves when at most half full.
 */
static void
hook_grow (void)
{
  generate (33);

  print_status ("initialize", mh_initialize ());
  printf ("created %zu\n", count_ok (0, 32, &create_generated));
  fault_next (FAULT_HEAP_REALLOC, 1);
  print_status ("create", create_generated (32));
  print_status ("create", create_generated (32));
  print_status ("uninitialize", mh_uninitialize ());

  code_free (generated);
}

static void
hook_shrink (void)
{
  generate (65);

  print_status ("initialize", mh_initialize ());
  printf ("created %zu\n", count_ok (0, 65, &create_generated));
  fault_next (FAULT_HEAP_REALLOC, 1);
  print_status ("remove", remove_generated (64));
  printf ("removed %zu\n", count_ok (0, 64, &remove_generated));
  print_status ("uninitialize", mh_uninitialize ());

  code_free (generated);
}

/* Enable the hook of a with the function failing after the skipped calls,
 * then without.
 */
static void
enable_failing_after (enum fault_function f, unsigned skips, unsigned n)
{
  print_status ("initialize", mh_initialize ());
  print_status ("create", create_a ());
  fault_next_after (f, skips, n);
  print_status ("enable", mh_enable_hook (address (&target_a)));
  print_handles ();
  print_result ("call", target_a (5));
  fault_next (f, 0);
  print_status ("disable", mh_disable_hook (address (&target_a)));
  print_status ("enable", mh_enable_hook (address (&target_a)));
  print_handles ();
  print_result ("call", target_a (5));
  print_status ("uninitialize", mh_uninitialize ());
}

static void
enable_failing (enum fault_function f, unsigned n)
{
  enable_failing_after (f, 0, n);
}

static void
thread_alloc (void)
{
  start_threads (1);
  enable_failing (FAULT_HEAP_ALLOC, 1);
  stop_threads ();
}

/* Note that the thread list starts with room for 128 threads.
 */
static void
thread_grow (void)
{
  start_threads (200);
  enable_failing (FAULT_HEAP_REALLOC, 1);
  stop_threads ();
}

static void
next_thread_first (void)
{
  enable_failing (FAULT_NEXT_THREAD, 1);

  print_status ("initialize", mh_initialize ());
  print_status ("create", create_a ());
  fault_next (FAULT_NEXT_THREAD, 1);
  print_status ("enable-all", mh_enable_hook (MH_ALL_HOOKS));
  print_result ("call", target_a (5));
  print_status ("uninitialize", mh_uninitialize ());
}

/* With the current thread and two others, at least one of the first two
 * threads is in the list when the third fails.
 */
static void
next_thread (void)
{
  start_threads (2);
  enable_failing_after (FAULT_NEXT_THREAD, 2, 1);
  stop_threads ();
}

/* The thread functions fail for every thread, which the engine then
 * leaves alone.
 */
static void
suspend_thread (void)
{
  start_threads (1);
  enable_failing (FAULT_SUSPEND_THREAD, (unsigned) -1);
  stop_threads ();
}

static void
thread_context (void)
{
  start_threads (1);
  enable_failing (FAULT_THREAD_CONTEXT, (unsigned) -1);
  stop_threads ();
}

static void
protect_enable (void)
{
  enable_failing (FAULT_VIRTUAL_PROTECT, 1);
}

static void
protect_all (void)
{
  print_status ("initialize", mh_initialize ());
  print_status ("create-a", create_a ());
  print_status ("create-b", create_b ());
  fault_next (FAULT_VIRTUAL_PROTECT, 1);
  print_status ("enable-all", mh_enable_hook (MH_ALL_HOOKS));
  print_result ("call-a", target_a (5));
  print_result ("call-b", target_b (5));
  print_status ("enable-all", mh_enable_hook (MH_ALL_HOOKS));
  print_result ("call-a", target_a (5));
  print_result ("call-b", target_b (5));
  print_status ("uninitialize", mh_uninitialize ());
}

static void
protect_remove (void)
{
  print_status ("initialize", mh_initialize ());
  print_status ("create", create_a ());
  print_status ("enable", mh_enable_hook (address (&target_a)));
  fault_next (FAULT_VIRTUAL_PROTECT, 1);
  print_status ("remove", mh_remove_hook (address (&target_a)));
  print_result ("call", target_a (5));
  print_status ("remove", mh_remove_hook (address (&target_a)));
  print_result ("call", target_a (5));
  print_status ("uninitialize", mh_uninitialize ());
}

static void
protect_uninitialize (void)
{
  print_status ("initialize", mh_initialize ());
  print_status ("create", create_a ());
  print_status ("enable", mh_enable_hook (address (&target_a)));
  fault_next (FAULT_VIRTUAL_PROTECT, 1);
  print_status ("uninitialize", mh_uninitialize ());
  print_result ("call", target_a (5));
  print_status ("uninitialize", mh_uninitialize ());
  print_result ("call", target_a (5));
}

/* On x64 the engine tries the next free region within reach, while on x86
 * it lets the system choose the address and has no alternative.
 */
static void
virtual_alloc (void)
{
  print_status ("initialize", mh_initialize ());
  fault_next (FAULT_VIRTUAL_ALLOC, 1);
  print_status ("create", create_a ());
  print_status ("uninitialize", mh_uninitialize ());
}

struct scenario
{
  const char* name;
  void      (*function) (void);
};

static const struct scenario scenarios[] = {
  {"heap-create",          &heap_create},
  {"hook-alloc",           &hook_alloc},
  {"hook-grow",            &hook_grow},
  {"hook-shrink",          &hook_shrink},
  {"thread-alloc",         &thread_alloc},
  {"thread-grow",          &thread_grow},
  {"next-thread-first",    &next_thread_first},
  {"next-thread",          &next_thread},
  {"suspend-thread",       &suspend_thread},
  {"thread-context",       &thread_context},
  {"protect-enable",       &protect_enable},
  {"protect-all",          &protect_all},
  {"protect-remove",       &protect_remove},
  {"protect-uninitialize", &protect_uninitialize},
  {"virtual-alloc",        &virtual_alloc}};

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
      fault_redirect ();
      scenarios[i].function ();
      return 0;
    }
  }

  fprintf (stderr, "error: invalid scenario '%s'\n", argv[1]);
  return 1;
}
