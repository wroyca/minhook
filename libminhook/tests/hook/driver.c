#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h> /* exit(), strtol() */
#include <string.h> /* strcmp(), strcspn(), strtok() */

#include <libminhook/minhook.h>

#undef NDEBUG
#include <assert.h>

/* Usage: argv[0]
 *
 * Read commands from stdin, one per line, run each against the library, and
 * print its outcome on a line of its own: the status name for an API call
 * and the returned value for a call to a function. The commands are:
 *
 * initialize
 * uninitialize
 * apply
 * create <target> [<detour>]
 * remove <target>
 * enable <target>
 * disable <target>
 * queue-enable <target>
 * queue-disable <target>
 * call <function> <integer>
 * original <function> <integer>
 *
 * Targets are the functions a and b, data (a data object), unmapped (an
 * address outside the address space), reserved (a page of address space
 * without memory), and all (MH_ALL_HOOKS). Detours are named after the
 * targets and default to the target's own. The detours of a and b add 1000
 * and 2000, respectively, to the result of the target's original function,
 * and those of data and unmapped are the addresses above.
 *
 * The call command calls the target function, which goes through the hook
 * if it is enabled. The original command calls the trampoline that create
 * stored and is only valid after a successful create.
 *
 * The functions a and b return x * 3 + 1 and (x ^ 0x55) - 7, respectively.
 */

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

/* Detours. Each calls the original function through the trampoline.
 */
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

static int data_object;

/* The highest 64K-aligned address is outside the user address space on
 * both x86 and x64, so querying it fails.
 */
#define UNMAPPED ((void*) (~(uintptr_t) 0 & ~(uintptr_t) 0xffff))

/* A named address that the commands operate on. The function and the
 * original are only set for the target functions.
 */
struct name_entry
{
  const char*       name;
  void*             address;
  target_function*  function;
  target_function** original;
};

static struct name_entry targets[] = {
  {"a",        NULL,         &target_a, &original_a},
  {"b",        NULL,         &target_b, &original_b},
  {"data",     &data_object, NULL,      NULL},
  {"unmapped", NULL,         NULL,      NULL},
  {"reserved", NULL,         NULL,      NULL},
  {"all",      MH_ALL_HOOKS, NULL,      NULL}};

static struct name_entry detours[] = {
  {"a",        NULL,         NULL,      NULL},
  {"b",        NULL,         NULL,      NULL},
  {"data",     &data_object, NULL,      NULL},
  {"unmapped", NULL,         NULL,      NULL}};

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
init_names (void)
{
  targets[0].address = address (&target_a);
  targets[1].address = address (&target_b);
  targets[3].address = UNMAPPED;
  targets[4].address = VirtualAlloc (NULL, 0x1000, MEM_RESERVE, PAGE_NOACCESS);
  assert (targets[4].address != NULL);

  detours[0].address = address (&detour_a);
  detours[1].address = address (&detour_b);
  detours[3].address = UNMAPPED;
}

/* Remove the hook without a retirement id, so that the command has the
 * same signature as the others.
 */
static enum mh_status
remove_hook (void* target)
{
  return mh_remove_hook (target, NULL);
}

/* The commands that apply a state change to a target.
 */
struct target_command
{
  const char*     name;
  enum mh_status (*function) (void*);
};

static const struct target_command target_commands[] = {
  {"remove",        &remove_hook},
  {"enable",        &mh_enable_hook},
  {"disable",       &mh_disable_hook},
  {"queue-enable",  &mh_queue_enable_hook},
  {"queue-disable", &mh_queue_disable_hook}};

#define COUNT(a) (sizeof (a) / sizeof ((a)[0]))

static char line[256]; /* The current command as read. */

static void
fail (void)
{
  fprintf (stderr, "error: invalid command '%s'\n", line);
  exit (1);
}

/* Return the entry with the name or fail if there is none.
 */
static const struct name_entry*
find_name (const struct name_entry* es, size_t n, const char* name)
{
  for (size_t i = 0; i != n; ++i)
  {
    if (strcmp (es[i].name, name) == 0)
      return &es[i];
  }

  fail ();
  return NULL; /* Unreachable. */
}

/* Return the integer or fail if it is not one.
 */
static int
parse_integer (const char* s)
{
  char* e;
  long r = strtol (s, &e, 10);

  if (*s == '\0' || *e != '\0')
    fail ();

  return (int) r;
}

static void
print_status (enum mh_status s)
{
  printf ("%s\n", mh_status_to_string (s));
}

int
main (void)
{
  init_names ();

  while (fgets (line, sizeof (line), stdin) != NULL)
  {
    line[strcspn (line, "\r\n")] = '\0';

    /* Split the command into words.
     */
    char  b[sizeof (line)];
    char* w[4];
    size_t n = 0;

    memcpy (b, line, sizeof (b));

    for (char* p = strtok (b, " "); p != NULL; p = strtok (NULL, " "))
    {
      if (n == COUNT (w))
        fail ();

      w[n++] = p;
    }

    if (n == 0)
      fail ();

    const char* c = w[0];

    /* Run the command.
     */
    if (strcmp (c, "initialize") == 0 ||
        strcmp (c, "uninitialize") == 0 ||
        strcmp (c, "apply") == 0)
    {
      if (n != 1)
        fail ();

      print_status (strcmp (c, "initialize") == 0   ? mh_initialize ()   :
                    strcmp (c, "uninitialize") == 0 ? mh_uninitialize () :
                                                      mh_apply_queued ());
    }
    else if (strcmp (c, "call") == 0 || strcmp (c, "original") == 0)
    {
      if (n != 3)
        fail ();

      const struct name_entry* e = find_name (targets, COUNT (targets), w[1]);
      int x = parse_integer (w[2]);

      if (e->function == NULL)
        fail ();

      if (strcmp (c, "call") == 0)
        printf ("%d\n", e->function (x));
      else
      {
        if (*e->original == NULL)
          fail ();

        printf ("%d\n", (*e->original) (x));
      }
    }
    else if (strcmp (c, "create") == 0)
    {
      if (n != 2 && n != 3)
        fail ();

      const struct name_entry* t = find_name (targets, COUNT (targets), w[1]);
      const struct name_entry* d = find_name (detours,
                                              COUNT (detours),
                                              w[n == 3 ? 2 : 1]);

      /* Note that the library stores the trampoline into the original through
       * void**, the same as the address() conversion.
       */
      print_status (mh_create_hook (t->address,
                                    d->address,
                                    (void**) t->original));
    }
    else
    {
      const struct target_command* tc = NULL;

      for (size_t i = 0; i != COUNT (target_commands); ++i)
      {
        if (strcmp (c, target_commands[i].name) == 0)
        {
          tc = &target_commands[i];
          break;
        }
      }

      if (tc == NULL || n != 2)
        fail ();

      const struct name_entry* t = find_name (targets, COUNT (targets), w[1]);
      print_status (tc->function (t->address));
    }

    fflush (stdout);
  }

  return 0;
}
