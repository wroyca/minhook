#include <stdio.h>
#include <stdlib.h> /* strtol() */

#include <libminhook/minhook.h>

/* Usage: argv[0] <integer>
 *
 * Print the name of the status with the integer value.
 */
int
main (int argc, char* argv[])
{
  if (argc != 2)
  {
    fprintf (stderr, "error: expected status value\n");
    return 1;
  }

  const char* s = argv[1];
  char* e;
  long v = strtol (s, &e, 10);

  if (*s == '\0' || *e != '\0')
  {
    fprintf (stderr, "error: invalid status value '%s'\n", s);
    return 1;
  }

  printf ("%s\n", mh_status_to_string ((enum mh_status) v));
  return 0;
}
