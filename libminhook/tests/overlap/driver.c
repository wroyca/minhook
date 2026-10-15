#include <stdio.h>
#include <stdint.h>
#include <string.h>  /* strcmp(), memcpy() */

#include <libminhook/minhook.h>

#include <common/code.h>

/* Usage: argv[0] <scenario>
 *
 * Hook two functions in a page whose code is close together and print the
 * outcome of each step on a line of its own: the status name for an API
 * call and the result for a call to a function. The scenarios are:
 *
 * patch        hook f and then g within the code that f's jump overwrites
 * relocated    hook f and then g within the code that f's trampoline
 *              relocates, and then the other way around
 * hot-patch    hook f, which ends with its jump over the padding after it,
 *              and then g, whose jump goes into that padding
 * adjacent     hook f and then g right after f's code
 * removed      hook f, then g within its jump, remove f, and hook g again
 *
 * The page is filled with int3 (see common/code.h) and the detours of f and
 * g add 1000 and 2000, respectively, to the result of the original
 * function.
 */

#define COUNT(a) (sizeof (a) / sizeof ((a)[0]))

typedef int target_function (void);

static target_function* original_f;
static target_function* original_g;

static int
detour_f (void)
{
  return original_f () + 1000;
}

static int
detour_g (void)
{
  return original_g () + 2000;
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

static void
print_status (const char* step, enum mh_status s)
{
  printf ("%s %s\n", step, mh_status_to_string (s));
}

static enum mh_status
create_f (void* p)
{
  return mh_create_hook (p, address (&detour_f), (void**) &original_f);
}

static enum mh_status
create_g (void* p)
{
  return mh_create_hook (p, address (&detour_g), (void**) &original_g);
}

/* mov eax, 7; ret and mov eax, 8; ret.
 */
static const uint8_t seven[] = {0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3};
static const uint8_t eight[] = {0xB8, 0x08, 0x00, 0x00, 0x00, 0xC3};

static void
patch (void)
{
  uint8_t* p = code_allocate (0x10, seven, sizeof (seven));

  print_status ("initialize", mh_initialize ());
  print_status ("create-f", create_f (p + 0x10));
  print_status ("create-g", create_g (p + 0x12));
  print_status ("uninitialize", mh_uninitialize ());

  code_free (p);
}

/* f is lea eax, [eax+7]; ret, whose trampoline relocates the 6 bytes of
 * lea, and g is at the last of them.
 */
static void
relocated (void)
{
  const uint8_t c[] = {0x8D, 0x80, 0x07, 0x00, 0x00, 0x00, 0xC3};
  uint8_t* p = code_allocate (0x10, c, sizeof (c));

  print_status ("initialize", mh_initialize ());
  print_status ("create-f", create_f (p + 0x10));
  print_status ("create-g", create_g (p + 0x15));
  print_status ("uninitialize", mh_uninitialize ());

  print_status ("initialize", mh_initialize ());
  print_status ("create-g", create_g (p + 0x15));
  print_status ("create-f", create_f (p + 0x10));
  print_status ("uninitialize", mh_uninitialize ());

  code_free (p);
}

/* f is ret followed by the padding, which its jump overwrites. g is a short
 * jump followed by code that is not padding, so its jump goes into the
 * padding above it, which overlaps f's.
 */
static void
hot_patch (void)
{
  const uint8_t c[] = {0xEB, 0x03, 0x31, 0xC0, 0xC3, 0xC3};
  uint8_t* p = code_allocate (0x18, c, sizeof (c));
  p[0x10] = 0xC3;

  print_status ("initialize", mh_initialize ());
  print_status ("create-f", create_f (p + 0x10));
  print_status ("create-g", create_g (p + 0x18));
  print_status ("uninitialize", mh_uninitialize ());

  code_free (p);
}

static void
adjacent (void)
{
  uint8_t* p = code_allocate (0x10, seven, sizeof (seven));
  memcpy (p + 0x16, eight, sizeof (eight));

  print_status ("initialize", mh_initialize ());
  print_status ("create-f", create_f (p + 0x10));
  print_status ("create-g", create_g (p + 0x16));
  print_status ("enable-all", mh_enable_hook (MH_ALL_HOOKS));
  printf ("call-f %d\n", call (p + 0x10));
  printf ("call-g %d\n", call (p + 0x16));
  print_status ("uninitialize", mh_uninitialize ());
  printf ("call-f %d\n", call (p + 0x10));
  printf ("call-g %d\n", call (p + 0x16));

  code_free (p);
}

static void
removed (void)
{
  uint8_t* p = code_allocate (0x10, seven, sizeof (seven));

  print_status ("initialize", mh_initialize ());
  print_status ("create-f", create_f (p + 0x10));
  print_status ("create-g", create_g (p + 0x12));
  print_status ("remove-f", mh_remove_hook (p + 0x10, NULL));
  print_status ("create-g", create_g (p + 0x12));
  print_status ("uninitialize", mh_uninitialize ());

  code_free (p);
}

struct scenario
{
  const char* name;
  void      (*function) (void);
};

static const struct scenario scenarios[] = {
  {"patch",     &patch},
  {"relocated", &relocated},
  {"hot-patch", &hot_patch},
  {"adjacent",  &adjacent},
  {"removed",   &removed}};

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
