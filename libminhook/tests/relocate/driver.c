#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>  /* strtoul() */
#include <string.h>  /* memcpy(), memset(), strcmp(), strlen() */
#include <stdbool.h>

#include <libminhook/minhook.h>

#include <common/code.h>

/* Usage: argv[0] [--no-hot-patch-area|--page-start] <byte>...
 *
 * Place the machine code that the bytes (in hex) make up as the target
 * function into a page with the following layout and hook it with a detour
 * that adds 1000 to the result of the original function:
 *
 * 0x000  padding (int3) above the target, the hot patch area
 * 0x010  target function, int () (the bytes, followed by int3)
 * 0x040  helper function: mov eax, 42; ret
 * 0x200  pointer to the helper function
 * 0x208  dword 7
 * 0x20c  scratch dword, zeroed before each call
 *
 * Note that the rest of the page is int3, which the library takes for
 * padding. Note also that the helper function is within the reach of the
 * short branches of the target function.
 *
 * With --no-hot-patch-area the area above the target is ret instead, which
 * is not padding. With --page-start the target is at 0x000, below the
 * padding of a page that is not executable (see common/code.h).
 *
 * Print the outcome in the following format:
 *
 * create <status>
 * [plain <result>]
 * [hooked <result>]
 * [restored <result>]
 * [removed <result>]
 *
 * If the hook is created, then print the results of calling the target
 * function with the hook disabled, enabled, disabled again, and removed.
 */

#define TARGET_OFFSET  0x010
#define HELPER_OFFSET  0x040
#define POINTER_OFFSET 0x200
#define DWORD_OFFSET   0x208
#define SCRATCH_OFFSET 0x20c

typedef int target_function (void);

static target_function* original;

static int
detour (void)
{
  return original () + 1000;
}

static uint8_t* page;
static uint8_t* target;

static int
call (void)
{
  memset (page + SCRATCH_OFFSET, 0, sizeof (uint32_t));

  target_function* f;
  memcpy (&f, &target, sizeof (f));
  return f ();
}

int
main (int argc, char* argv[])
{
  /* Parse the bytes.
   */
  int i = 1;
  bool no_hot_patch_area = false;
  bool page_start = false;

  if (argc > i && strcmp (argv[i], "--no-hot-patch-area") == 0)
  {
    no_hot_patch_area = true;
    ++i;
  }
  else if (argc > i && strcmp (argv[i], "--page-start") == 0)
  {
    page_start = true;
    ++i;
  }

  size_t offset = page_start ? 0 : TARGET_OFFSET;

  uint8_t code[HELPER_OFFSET - TARGET_OFFSET];
  size_t n = 0;

  for (; i != argc; ++i)
  {
    const char* a = argv[i];
    char* e;
    unsigned long v = strtoul (a, &e, 16);

    if (strlen (a) != 2 || *e != '\0' || n == sizeof (code))
    {
      fprintf (stderr, "error: invalid byte '%s'\n", a);
      return 1;
    }

    code[n++] = (uint8_t) v;
  }

  if (n == 0)
  {
    fprintf (stderr, "error: expected bytes\n");
    return 1;
  }

  /* Lay out the page.
   */
  {
    const uint8_t helper[] = {0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3};
    const uint32_t seven = 7;

    page = code_allocate (offset, code, n);
    memcpy (page + HELPER_OFFSET, helper, sizeof (helper));

    void* h = page + HELPER_OFFSET;
    memcpy (page + POINTER_OFFSET, &h, sizeof (h));
    memcpy (page + DWORD_OFFSET, &seven, sizeof (seven));

    if (no_hot_patch_area)
      memset (page, 0xC3, TARGET_OFFSET);
  }

  /* Hook the target and call it in each state.
   */
  target = page + offset;
  void* t = target;
  void* d;
  {
    target_function* f = &detour;
    memcpy (&d, &f, sizeof (d));
  }

  enum mh_status s = mh_initialize ();
  assert (s == MH_OK);

  s = mh_create_hook (t, d, (void**) &original);
  printf ("create %s\n", mh_status_to_string (s));

  if (s == MH_OK)
  {
    printf ("plain %d\n", call ());

    s = mh_enable_hook (t);
    assert (s == MH_OK);
    printf ("hooked %d\n", call ());

    s = mh_disable_hook (t);
    assert (s == MH_OK);
    printf ("restored %d\n", call ());

    s = mh_enable_hook (t);
    assert (s == MH_OK);
    s = mh_remove_hook (t);
    assert (s == MH_OK);
    printf ("removed %d\n", call ());
  }

  s = mh_uninitialize ();
  assert (s == MH_OK);

  code_free (page);
  return 0;
}
