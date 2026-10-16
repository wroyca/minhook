#include <stdio.h>
#include <stdint.h>
#include <stdlib.h> /* strtoul() */
#include <string.h> /* memcpy() */

#include <libminhook/minhook.h>

#include <common/code.h>

/* Usage: argv[0] <count>
 *
 * Generate the number of functions, the function i being mov eax, i; ret,
 * hook each with a detour that returns -1, and print the number of
 * functions that pass each step in the following format:
 *
 * created <n>
 * hooked <n>
 * restored <n>
 * removed <n>
 * reclaimed <n>
 *
 * The steps create the hooks, enable them all at once (the functions then
 * return -1), disable them all at once (the functions then return i),
 * remove them in the order of creation (the functions still return i), and
 * reclaim their trampolines in the same order.
 *
 * The count is at most 256.
 */

#define FUNCTION_SIZE 16
#define MAX_COUNT     (CODE_PAGE_SIZE / FUNCTION_SIZE)

typedef int target_function (void);

static int
detour (void)
{
  return -1;
}

/* ISO C has no conversion between function and object pointers, so we
 * copy the representation (they are the same on Windows).
 */
static int
call (uint8_t* p)
{
  target_function* f;
  memcpy (&f, &p, sizeof (f));
  return f ();
}

/* Return the number of functions that return the value or, if the value
 * is -2, their own index.
 */
static size_t
count_returning (uint8_t* p, size_t n, int v)
{
  size_t r = 0;

  for (size_t i = 0; i != n; ++i)
  {
    if (call (p + i * FUNCTION_SIZE) == (v == -2 ? (int) i : v))
      ++r;
  }

  return r;
}

int
main (int argc, char* argv[])
{
  char* e = NULL;
  unsigned long n = argc == 2 ? strtoul (argv[1], &e, 10) : 0;

  if (argc != 2 || *argv[1] == '\0' || *e != '\0' || n == 0 || n > MAX_COUNT)
  {
    fprintf (stderr, "error: expected count between 1 and %d\n", MAX_COUNT);
    return 1;
  }

  /* Generate the functions.
   */
  uint8_t* p = code_allocate (0, NULL, 0);

  for (size_t i = 0; i != n; ++i)
  {
    const uint32_t v = (uint32_t) i;
    uint8_t* f = p + i * FUNCTION_SIZE;

    f[0] = 0xB8;
    memcpy (f + 1, &v, sizeof (v));
    f[5] = 0xC3;
  }

  void* d;
  {
    target_function* f = &detour;
    memcpy (&d, &f, sizeof (d));
  }

  enum mh_status s = mh_initialize ();
  assert (s == MH_OK);

  /* Run the steps.
   */
  size_t c = 0;
  for (size_t i = 0; i != n; ++i)
  {
    if (mh_create_hook (p + i * FUNCTION_SIZE, d, NULL) == MH_OK)
      ++c;
  }
  printf ("created %zu\n", c);

  s = mh_enable_hook (MH_ALL_HOOKS);
  assert (s == MH_OK);
  printf ("hooked %zu\n", count_returning (p, n, -1));

  s = mh_disable_hook (MH_ALL_HOOKS);
  assert (s == MH_OK);
  printf ("restored %zu\n", count_returning (p, n, -2));

  mh_retirement_id ids[MAX_COUNT];

  c = 0;
  for (size_t i = 0; i != n; ++i)
  {
    if (mh_remove_hook (p + i * FUNCTION_SIZE, &ids[i]) == MH_OK &&
        call (p + i * FUNCTION_SIZE) == (int) i)
      ++c;
  }
  printf ("removed %zu\n", c);

  c = 0;
  for (size_t i = 0; i != n; ++i)
  {
    if (mh_reclaim_trampoline (ids[i]) == MH_OK)
      ++c;
  }
  printf ("reclaimed %zu\n", c);

  s = mh_uninitialize ();
  assert (s == MH_OK);

  code_free (p);
  return 0;
}
