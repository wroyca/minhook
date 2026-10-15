#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdio.h>
#include <string.h> /* strcmp(), strlen(), memcpy() */
#include <stdbool.h>

#include <libminhook/minhook.h>

#undef NDEBUG
#include <assert.h>

/* Usage: argv[0] [--no-target] <module> <function>
 *
 * Hook the function that the loaded module exports under the name with a
 * detour that returns 42. The function takes no arguments and returns a
 * DWORD (GetCurrentProcessId(), for example). Print the outcome in the
 * following format:
 *
 * create <status>
 * [target 1|0]
 * [hooked <result>]
 * [original 1|0]
 *
 * If the hook is created, then print whether the target address that
 * mh_create_hook_api_ex() returned is the export (unless --no-target is
 * specified, in which case use mh_create_hook_api()), the result of calling
 * the function with the hook enabled, and whether the original function
 * returns what the function returned before hooking.
 *
 * The module name is ASCII.
 */

typedef DWORD WINAPI export_function (void);

static export_function* original;

static DWORD WINAPI
detour (void)
{
  return 42;
}

/* ISO C has no conversion between function and object pointers, so we
 * copy the representation (they are the same on Windows).
 */
static void*
address (export_function* f)
{
  void* r;
  memcpy (&r, &f, sizeof (r));
  return r;
}

/* Return the function that the module exports under the name or NULL if
 * there is no such module or function.
 */
static export_function*
find_export (const wchar_t* m, const char* n)
{
  HMODULE h = GetModuleHandleW (m);

  if (h == NULL)
    return NULL;

  FARPROC p = GetProcAddress (h, n);
  export_function* r;
  memcpy (&r, &p, sizeof (r));
  return r;
}

int
main (int argc, char* argv[])
{
  int i = 1;
  bool no_target = argc > i && strcmp (argv[i], "--no-target") == 0;

  if (no_target)
    ++i;

  if (argc - i != 2)
  {
    fprintf (stderr, "error: expected module and function\n");
    return 1;
  }

  /* Widen the module name.
   */
  wchar_t m[MAX_PATH];
  const char* mn = argv[i];
  size_t n = strlen (mn);

  if (n >= MAX_PATH)
  {
    fprintf (stderr, "error: invalid module '%s'\n", mn);
    return 1;
  }

  for (size_t j = 0; j != n + 1; ++j)
    m[j] = (wchar_t) (unsigned char) mn[j];

  const char* fn = argv[i + 1];

  /* Call the function before hooking since the calls after enabling go
   * through the hook.
   */
  export_function* e = find_export (m, fn);
  DWORD v = e != NULL ? e () : 0;

  assert (mh_initialize () == MH_OK);

  void* t = NULL;
  void* d = address (&detour);
  void** o = (void**) &original;

  enum mh_status s = no_target
    ? mh_create_hook_api (m, fn, d, o)
    : mh_create_hook_api_ex (m, fn, d, o, &t);

  printf ("create %s\n", mh_status_to_string (s));

  if (s == MH_OK)
  {
    if (!no_target)
      printf ("target %d\n", t == address (e) ? 1 : 0);

    assert (mh_enable_hook (address (e)) == MH_OK);
    printf ("hooked %lu\n", (unsigned long) e ());
    printf ("original %d\n", original () == v ? 1 : 0);
    assert (mh_remove_hook (address (e), NULL) == MH_OK);
  }

  assert (mh_uninitialize () == MH_OK);
  return 0;
}
