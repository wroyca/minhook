#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <libminhook/version.h>
#include <libminhook/minhook.h>

#undef NDEBUG
#include <assert.h>

#ifdef _WIN32
#define tmpfile mytmpfile
static FILE *mytmpfile ();
#endif

int main ()
{
  char b[256];

  /* Basics.
   */
  {
    FILE *o = tmpfile ();
    assert (say_hello (o, "World") > 0);
    rewind (o);
    assert (fread (b, 1, sizeof (b), o) == 14 &&
            strncmp (b, "Hello, World!\n", 14) == 0);
    fclose (o);
  }

  /* Empty name.
   */
  {
    FILE *o = tmpfile ();
    assert (say_hello (o, "") < 0 && errno == EINVAL);
    fclose (o);
  }

  return 0;
}

#ifdef _WIN32
#include <windows.h>
#include <fcntl.h>
#include <io.h>

FILE *mytmpfile ()
{
  char d[MAX_PATH + 1], p[MAX_PATH + 1];
  if (GetTempPathA (sizeof (d), d) == 0 ||
      GetTempFileNameA (d, "tmp", 0, p) == 0)
    return NULL;

  HANDLE h = CreateFileA (p,
                          GENERIC_READ | GENERIC_WRITE,
                          0,
                          NULL,
                          CREATE_ALWAYS,
                          FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                          NULL);
  if (h == INVALID_HANDLE_VALUE)
    return NULL;

  int fd = _open_osfhandle ((intptr_t) h, _O_RDWR);
  if (fd == -1)
    return NULL;

  FILE *f = _fdopen (fd, "wb+");
  if (f == NULL)
    _close (fd);

  return f;
}
#endif
