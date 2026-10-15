#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>  /* strtoul() */
#include <string.h>  /* memcpy(), memset(), strcmp(), strlen() */
#include <stdbool.h>

#include <libminhook/minhook.h>

#undef NDEBUG
#include <assert.h>

/* Usage: argv[0] [--start] <protection> <byte>...
 *
 * Place the machine code that the bytes (in hex) make up as the target
 * function at the end of a page and hook it with a detour that adds 1000 to
 * the result of the original function. The page is followed by another
 * page, both filled with int3, which the library takes for padding.
 *
 * With --start the target is at the start of the second page, so that the
 * padding above it (the hot patch area) is at the end of the first page.
 *
 * The page with the target is execute-read and the other page has the
 * protection, which is one of noaccess, readonly, execute-read, and
 * execute-readwrite.
 *
 * Print the outcome in the following format:
 *
 * create <status>
 * [plain <result>]
 * [hooked <result>]
 * [restored <result>]
 * [removed <result>]
 * protection <target-page> <other-page>
 *
 * If the hook is created, then print the results of calling the target
 * function with the hook disabled, enabled, disabled again, and removed.
 * Then print the protections of the pages.
 */

#define PAGE_SIZE 0x1000

struct protection
{
  const char* name;
  DWORD       value;
};

static const struct protection protections[] = {
  {"noaccess",          PAGE_NOACCESS},
  {"readonly",          PAGE_READONLY},
  {"execute-read",      PAGE_EXECUTE_READ},
  {"execute-readwrite", PAGE_EXECUTE_READWRITE}};

#define COUNT(a) (sizeof (a) / sizeof ((a)[0]))

static const char*
protection_name (DWORD v)
{
  for (size_t i = 0; i != COUNT (protections); ++i)
  {
    if (protections[i].value == v)
      return protections[i].name;
  }

  return "unknown";
}

/* Return the protection of the page at the address.
 */
static DWORD
query (const void* p)
{
  MEMORY_BASIC_INFORMATION i;
  SIZE_T n = VirtualQuery (p, &i, sizeof (i));
  assert (n != 0);
  return i.Protect;
}

static void
protect (void* p, DWORD v)
{
  DWORD o;
  BOOL r = VirtualProtect (p, PAGE_SIZE, v, &o);
  assert (r);
}

typedef int target_function (void);

static target_function* original;

static int
detour (void)
{
  return original () + 1000;
}

static uint8_t* target;

static int
call (void)
{
  target_function* f;
  memcpy (&f, &target, sizeof (f));
  return f ();
}

int
main (int argc, char* argv[])
{
  /* Parse the arguments.
   */
  int i = 1;
  bool start = false;

  if (argc > i && strcmp (argv[i], "--start") == 0)
  {
    start = true;
    ++i;
  }

  if (argc == i)
  {
    fprintf (stderr, "error: expected protection\n");
    return 1;
  }

  const struct protection* other = NULL;

  for (size_t j = 0; j != COUNT (protections); ++j)
  {
    if (strcmp (argv[i], protections[j].name) == 0)
      other = &protections[j];
  }

  if (other == NULL)
  {
    fprintf (stderr, "error: invalid protection '%s'\n", argv[i]);
    return 1;
  }

  ++i;

  uint8_t code[16];
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

  /* Lay out the pages.
   */
  uint8_t* pages = (uint8_t*) VirtualAlloc (NULL,
                                            2 * PAGE_SIZE,
                                            MEM_COMMIT | MEM_RESERVE,
                                            PAGE_EXECUTE_READWRITE);
  assert (pages != NULL);

  memset (pages, 0xCC, 2 * PAGE_SIZE);

  uint8_t* page;       /* Page with the target. */
  uint8_t* other_page;

  if (start)
  {
    page = pages + PAGE_SIZE;
    other_page = pages;
    target = page;
  }
  else
  {
    page = pages;
    other_page = pages + PAGE_SIZE;
    target = page + PAGE_SIZE - n;
  }

  memcpy (target, code, n);

  protect (page, PAGE_EXECUTE_READ);
  protect (other_page, other->value);

  /* Hook the target and call it in each state.
   */
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
    s = mh_remove_hook (t, NULL);
    assert (s == MH_OK);
    printf ("removed %d\n", call ());
  }

  s = mh_uninitialize ();
  assert (s == MH_OK);

  printf ("protection %s %s\n",
          protection_name (query (page)),
          protection_name (query (other_page)));

  BOOL r = VirtualFree (pages, 0, MEM_RELEASE);
  assert (r);
  return 0;
}
