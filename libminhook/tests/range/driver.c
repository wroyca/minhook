#include <stdio.h>
#include <stdint.h>
#include <string.h>  /* strcmp(), memcpy(), memset() */
#include <stdbool.h>

#include <libminhook/minhook.h>

#include <common/code.h>
#include <common/fault.h>

/* Usage: argv[0] <scenario>
 *
 * On x64 the library allocates the trampoline of a hook within 1 GiB of the
 * target, so that the relative jumps between the two reach. Run the
 * scenario with a target function far from the other code of the process
 * and print the outcome of each step on a line of its own. The scenarios
 * are:
 *
 * far          hook a function near the other code and then the far one
 * far-first    hook the far function and then one near the other code
 * below        hook the far function with the address space below it
 *              reserved
 * below-retry  as below with the first trampoline block allocation failing
 * reserved     hook the far function with the address space around it
 *              reserved
 * rip-relative hook the far function with the address space below it
 *              reserved and code that reads from 2 GiB below it
 * low          hook a function one allocation granule above the first
 *              1 GiB of the address space
 * high         hook a function within 1 GiB of the end of the address space
 *
 * The target functions are mov eax, 42; ret, except in rip-relative where
 * it is mov eax, [rip-0x7ffffff0]; ret, and their detours add 1000 to the
 * result of the original function. The below scenarios also print
 * whether the trampoline is above the target.
 */

#define COUNT(a) (sizeof (a) / sizeof ((a)[0]))

/* The distance within which the library allocates trampolines and the
 * allocation granularity.
 */
#define RANGE       ((uintptr_t) 0x40000000)
#define GRANULARITY ((uintptr_t) 0x10000)

typedef int target_function (void);

static target_function* original_near;
static target_function* original_far;

static int
detour_near (void)
{
  return original_near () + 1000;
}

static int
detour_far (void)
{
  return original_far () + 1000;
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

static int
call (void* p)
{
  target_function* f;
  memcpy (&f, &p, sizeof (f));
  return f ();
}

static const uint8_t function_code[] = {0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3};

static const uint8_t rip_relative_code[] = {
  0x8B, 0x05, 0x10, 0x00, 0x00, 0x80, 0xC3};

/* Allocate a page with the code at the first free address from 16 TiB up in
 * 1 TiB steps, which is far from the other code of the process.
 */
static uint8_t*
allocate_far_code (const uint8_t* code, size_t n)
{
  for (uintptr_t a = (uintptr_t) 1 << 44; a < (uintptr_t) 1 << 47;
       a += (uintptr_t) 1 << 40)
  {
    uint8_t* p = (uint8_t*) VirtualAlloc ((void*) a,
                                          CODE_PAGE_SIZE,
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
    if (p != NULL)
    {
      memset (p, 0xCC, CODE_PAGE_SIZE);
      memcpy (p, code, n);
      return p;
    }
  }

  assert (0);
  return NULL;
}

static uint8_t*
allocate_far (void)
{
  return allocate_far_code (function_code, sizeof (function_code));
}

/* Reservations of the free address space.
 */
static void* reservations[4096];
static size_t reservation_count;

/* Reserve the free address space between the addresses.
 */
static void
reserve (uintptr_t lo, uintptr_t hi)
{
  for (uintptr_t a = (lo + GRANULARITY - 1) & ~(GRANULARITY - 1); a < hi; )
  {
    MEMORY_BASIC_INFORMATION i;
    if (VirtualQuery ((void*) a, &i, sizeof (i)) == 0)
      break;

    uintptr_t e = (uintptr_t) i.BaseAddress + i.RegionSize;

    if (e > hi)
      e = hi;

    if (i.State == MEM_FREE)
    {
      assert (reservation_count != COUNT (reservations));

      void* p = VirtualAlloc ((void*) a, e - a, MEM_RESERVE, PAGE_NOACCESS);
      assert (p != NULL);
      reservations[reservation_count++] = p;
    }

    a = (e + GRANULARITY - 1) & ~(GRANULARITY - 1);
  }
}

static void
release (void)
{
  for (size_t i = 0; i != reservation_count; ++i)
  {
    BOOL r = VirtualFree (reservations[i], 0, MEM_RELEASE);
    assert (r);
  }

  reservation_count = 0;
}

static void
print_status (const char* step, enum mh_status s)
{
  printf ("%s %s\n", step, mh_status_to_string (s));
}

static void
hook_far (void)
{
  uint8_t* n = code_allocate (0, function_code, sizeof (function_code));
  uint8_t* f = allocate_far ();

  print_status ("initialize", mh_initialize ());
  print_status ("create-near",
                mh_create_hook (n,
                                address (&detour_near),
                                (void**) &original_near));
  print_status ("create-far",
                mh_create_hook (f,
                                address (&detour_far),
                                (void**) &original_far));
  print_status ("enable-all", mh_enable_hook (MH_ALL_HOOKS));
  printf ("call-near %d\n", call (n));
  printf ("call-far %d\n", call (f));
  print_status ("uninitialize", mh_uninitialize ());

  VirtualFree (f, 0, MEM_RELEASE);
  code_free (n);
}

static void
below (bool retry)
{
  uint8_t* f = allocate_far ();
  uintptr_t o = (uintptr_t) f;

  reserve (o - RANGE - GRANULARITY, o);

  if (retry)
    fault_next (FAULT_VIRTUAL_ALLOC, 1);

  void* tramp;
  print_status ("initialize", mh_initialize ());
  print_status ("create",
                mh_create_hook (f, address (&detour_far), &tramp));
  memcpy (&original_far, &tramp, sizeof (tramp));
  printf ("above %d\n", (uintptr_t) tramp > o ? 1 : 0);
  print_status ("enable", mh_enable_hook (f));
  printf ("call %d\n", call (f));
  print_status ("uninitialize", mh_uninitialize ());

  release ();
  VirtualFree (f, 0, MEM_RELEASE);
}

static void
hook_below (void)
{
  below (false);
}

static void
hook_below_retry (void)
{
  below (true);
}

/* The trampoline is above the target, so the code's destination is out of
 * the reach of the relocated displacement. Note that the code never runs.
 */
static void
hook_rip_relative (void)
{
  uint8_t* f = allocate_far_code (rip_relative_code,
                                  sizeof (rip_relative_code));
  uintptr_t o = (uintptr_t) f;

  reserve (o - RANGE - GRANULARITY, o);

  print_status ("initialize", mh_initialize ());
  print_status ("create",
                mh_create_hook (f,
                                address (&detour_far),
                                (void**) &original_far));
  print_status ("uninitialize", mh_uninitialize ());

  release ();
  VirtualFree (f, 0, MEM_RELEASE);
}

static void
hook_reserved (void)
{
  uint8_t* f = allocate_far ();
  uintptr_t o = (uintptr_t) f;

  reserve (o - RANGE - GRANULARITY, o);
  reserve (o + CODE_PAGE_SIZE, o + RANGE + GRANULARITY);

  print_status ("initialize", mh_initialize ());
  print_status ("create",
                mh_create_hook (f,
                                address (&detour_far),
                                (void**) &original_far));
  print_status ("uninitialize", mh_uninitialize ());

  release ();
  VirtualFree (f, 0, MEM_RELEASE);
}

static void
hook_far_first (void)
{
  uint8_t* f = allocate_far ();
  uint8_t* n = code_allocate (0, function_code, sizeof (function_code));

  print_status ("initialize", mh_initialize ());
  print_status ("create-far",
                mh_create_hook (f,
                                address (&detour_far),
                                (void**) &original_far));
  print_status ("create-near",
                mh_create_hook (n,
                                address (&detour_near),
                                (void**) &original_near));
  print_status ("enable-all", mh_enable_hook (MH_ALL_HOOKS));
  printf ("call-far %d\n", call (f));
  printf ("call-near %d\n", call (n));
  print_status ("uninitialize", mh_uninitialize ());

  code_free (n);
  VirtualFree (f, 0, MEM_RELEASE);
}

/* Hook the function at the page and print the outcome.
 */
static void
hook_at (uint8_t* p)
{
  memset (p, 0xCC, CODE_PAGE_SIZE);
  memcpy (p, function_code, sizeof (function_code));

  print_status ("initialize", mh_initialize ());
  print_status ("create",
                mh_create_hook (p,
                                address (&detour_far),
                                (void**) &original_far));
  print_status ("enable", mh_enable_hook (p));
  printf ("call %d\n", call (p));
  print_status ("uninitialize", mh_uninitialize ());

  VirtualFree (p, 0, MEM_RELEASE);
}

/* The range below the function then reaches down to the lowest address
 * that the system allocates.
 */
static void
hook_low (void)
{
  uint8_t* p = (uint8_t*) VirtualAlloc ((void*) (RANGE + GRANULARITY),
                                        CODE_PAGE_SIZE,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
  assert (p != NULL);
  hook_at (p);
}

static void
hook_high (void)
{
  uint8_t* p = (uint8_t*) VirtualAlloc (NULL,
                                        CODE_PAGE_SIZE,
                                        MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,
                                        PAGE_EXECUTE_READWRITE);
  assert (p != NULL);
  hook_at (p);
}

struct scenario
{
  const char* name;
  void      (*function) (void);
};

static const struct scenario scenarios[] = {
  {"far",          &hook_far},
  {"far-first",    &hook_far_first},
  {"below",        &hook_below},
  {"below-retry",  &hook_below_retry},
  {"rip-relative", &hook_rip_relative},
  {"reserved",     &hook_reserved},
  {"low",          &hook_low},
  {"high",         &hook_high}};

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
