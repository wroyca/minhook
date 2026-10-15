#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h> /* NTSTATUS */

#include <stdint.h>
#include <string.h> /* strcmp(), memcpy() */
#include <stdbool.h>

#include <libminhook/minhook.h>

#undef NDEBUG
#include <assert.h>

/* Failures of the Win32 functions that the library calls.
 *
 * We make a function fail by redirecting its entry in the import address
 * table of the module that contains the library to a wrapper. The wrapper
 * passes the number of calls that a test requests to skip on to the
 * function, then fails the number of calls that it requests to fail, the
 * way the function documents, and passes the rest on to the function
 * again.
 *
 * We also redirect CloseHandle(), which never fails, to count the thread
 * handles that the library holds (see fault_thread_handles).
 */
enum fault_function
{
  FAULT_HEAP_CREATE,
  FAULT_HEAP_ALLOC,
  FAULT_HEAP_REALLOC,
  FAULT_VIRTUAL_ALLOC,
  FAULT_VIRTUAL_PROTECT,
  FAULT_NEXT_THREAD,
  FAULT_SUSPEND_THREAD,
  FAULT_THREAD_CONTEXT,
  FAULT_CLOSE_HANDLE,
  FAULT_COUNT
};

/* An import of the library that we redirect.
 */
struct fault_import
{
  const char* name;
  FARPROC     wrapper;
  FARPROC     function; /* The function that the import resolved to. */
  unsigned    skips;    /* Number of the next calls to pass on. */
  unsigned    failures; /* Number of the calls to fail after those. */
};

static struct fault_import fault_imports[FAULT_COUNT];

/* Number of the thread handles that NtGetNextThread() returned to the
 * library and that it has not closed yet. Note that the library closes no
 * other handles.
 */
static long fault_thread_handles;

/* Pass the next skips calls to the function on and fail the failures
 * calls after them.
 */
static void
fault_next_after (enum fault_function f, unsigned skips, unsigned failures)
{
  fault_imports[f].skips = skips;
  fault_imports[f].failures = failures;
}

static void
fault_next (enum fault_function f, unsigned failures)
{
  fault_next_after (f, 0, failures);
}

/* Return true if the call should fail, counting it.
 */
static bool
fault_fail (enum fault_function f)
{
  struct fault_import* i = &fault_imports[f];

  if (i->skips != 0)
  {
    i->skips--;
    return false;
  }

  if (i->failures == 0)
    return false;

  i->failures--;
  return true;
}

/* The wrappers.
 */
static HANDLE WINAPI
fault_heap_create (DWORD o, SIZE_T i, SIZE_T m)
{
  if (fault_fail (FAULT_HEAP_CREATE))
  {
    SetLastError (ERROR_NOT_ENOUGH_MEMORY);
    return NULL;
  }

  return ((HANDLE (WINAPI*) (DWORD, SIZE_T, SIZE_T))
          fault_imports[FAULT_HEAP_CREATE].function) (o, i, m);
}

static LPVOID WINAPI
fault_heap_alloc (HANDLE h, DWORD f, SIZE_T n)
{
  if (fault_fail (FAULT_HEAP_ALLOC))
    return NULL;

  return ((LPVOID (WINAPI*) (HANDLE, DWORD, SIZE_T))
          fault_imports[FAULT_HEAP_ALLOC].function) (h, f, n);
}

static LPVOID WINAPI
fault_heap_realloc (HANDLE h, DWORD f, LPVOID p, SIZE_T n)
{
  if (fault_fail (FAULT_HEAP_REALLOC))
    return NULL;

  return ((LPVOID (WINAPI*) (HANDLE, DWORD, LPVOID, SIZE_T))
          fault_imports[FAULT_HEAP_REALLOC].function) (h, f, p, n);
}

static LPVOID WINAPI
fault_virtual_alloc (LPVOID a, SIZE_T n, DWORD t, DWORD p)
{
  if (fault_fail (FAULT_VIRTUAL_ALLOC))
  {
    SetLastError (ERROR_INVALID_ADDRESS);
    return NULL;
  }

  return ((LPVOID (WINAPI*) (LPVOID, SIZE_T, DWORD, DWORD))
          fault_imports[FAULT_VIRTUAL_ALLOC].function) (a, n, t, p);
}

static BOOL WINAPI
fault_virtual_protect (LPVOID a, SIZE_T n, DWORD p, PDWORD o)
{
  if (fault_fail (FAULT_VIRTUAL_PROTECT))
  {
    SetLastError (ERROR_ACCESS_DENIED);
    return FALSE;
  }

  return ((BOOL (WINAPI*) (LPVOID, SIZE_T, DWORD, PDWORD))
          fault_imports[FAULT_VIRTUAL_PROTECT].function) (a, n, p, o);
}

static NTSTATUS NTAPI
fault_next_thread (HANDLE p, HANDLE t, ACCESS_MASK a, ULONG h, ULONG f,
                   PHANDLE n)
{
  if (fault_fail (FAULT_NEXT_THREAD))
    return (NTSTATUS) 0xC0000022L; /* STATUS_ACCESS_DENIED */

  NTSTATUS r = ((NTSTATUS (NTAPI*) (HANDLE, HANDLE, ACCESS_MASK, ULONG,
                                    ULONG, PHANDLE))
                fault_imports[FAULT_NEXT_THREAD].function) (p, t, a, h, f, n);

  if (r >= 0)
    fault_thread_handles++;

  return r;
}

static DWORD WINAPI
fault_suspend_thread (HANDLE t)
{
  if (fault_fail (FAULT_SUSPEND_THREAD))
  {
    SetLastError (ERROR_ACCESS_DENIED);
    return (DWORD) -1;
  }

  return ((DWORD (WINAPI*) (HANDLE))
          fault_imports[FAULT_SUSPEND_THREAD].function) (t);
}

static BOOL WINAPI
fault_thread_context (HANDLE t, LPCONTEXT c)
{
  if (fault_fail (FAULT_THREAD_CONTEXT))
  {
    SetLastError (ERROR_ACCESS_DENIED);
    return FALSE;
  }

  return ((BOOL (WINAPI*) (HANDLE, LPCONTEXT))
          fault_imports[FAULT_THREAD_CONTEXT].function) (t, c);
}

static BOOL WINAPI
fault_close_handle (HANDLE h)
{
  fault_thread_handles--;

  return ((BOOL (WINAPI*) (HANDLE))
          fault_imports[FAULT_CLOSE_HANDLE].function) (h);
}

static struct fault_import fault_imports[FAULT_COUNT] = {
  {"HeapCreate",       (FARPROC) &fault_heap_create,     NULL, 0, 0},
  {"HeapAlloc",        (FARPROC) &fault_heap_alloc,      NULL, 0, 0},
  {"HeapReAlloc",      (FARPROC) &fault_heap_realloc,    NULL, 0, 0},
  {"VirtualAlloc",     (FARPROC) &fault_virtual_alloc,   NULL, 0, 0},
  {"VirtualProtect",   (FARPROC) &fault_virtual_protect, NULL, 0, 0},
  {"NtGetNextThread",  (FARPROC) &fault_next_thread,     NULL, 0, 0},
  {"SuspendThread",    (FARPROC) &fault_suspend_thread,  NULL, 0, 0},
  {"GetThreadContext", (FARPROC) &fault_thread_context,  NULL, 0, 0},
  {"CloseHandle",      (FARPROC) &fault_close_handle,    NULL, 0, 0}};

/* Redirect the imports of the module that contains the library to the
 * wrappers.
 */
static void
fault_redirect (void)
{
  /* Find the module through the address of one of the library's functions.
   */
  HMODULE m;
  {
    enum mh_status (*f) (void) = &mh_initialize;
    const wchar_t* a;
    memcpy (&a, &f, sizeof (a));

    BOOL r = GetModuleHandleExW (GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                 GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                 a,
                                 &m);
    assert (r);
  }

  /* Walk the import descriptors and patch the address table entry of each
   * import that we redirect.
   */
  const uint8_t* b = (const uint8_t*) m;
  const IMAGE_DOS_HEADER* dh = (const IMAGE_DOS_HEADER*) b;
  const IMAGE_NT_HEADERS* nh = (const IMAGE_NT_HEADERS*) (b + dh->e_lfanew);
  const IMAGE_DATA_DIRECTORY* dd =
    &nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

  for (const IMAGE_IMPORT_DESCRIPTOR* id =
         (const IMAGE_IMPORT_DESCRIPTOR*) (b + dd->VirtualAddress);
       id->Name != 0;
       ++id)
  {
    const IMAGE_THUNK_DATA* n = (const IMAGE_THUNK_DATA*) (
      b + (id->OriginalFirstThunk != 0 ? id->OriginalFirstThunk
                                       : id->FirstThunk));
    IMAGE_THUNK_DATA* f = (IMAGE_THUNK_DATA*) (b + id->FirstThunk);

    for (; n->u1.AddressOfData != 0; ++n, ++f)
    {
      if (IMAGE_SNAP_BY_ORDINAL (n->u1.Ordinal))
        continue;

      const IMAGE_IMPORT_BY_NAME* in =
        (const IMAGE_IMPORT_BY_NAME*) (b + n->u1.AddressOfData);

      for (size_t i = 0; i != FAULT_COUNT; ++i)
      {
        struct fault_import* im = &fault_imports[i];

        if (strcmp ((const char*) in->Name, im->name) != 0)
          continue;

        DWORD o;
        BOOL r = VirtualProtect (&f->u1.Function,
                                 sizeof (f->u1.Function),
                                 PAGE_READWRITE,
                                 &o);
        assert (r);

        memcpy (&im->function, &f->u1.Function, sizeof (im->function));
        memcpy (&f->u1.Function, &im->wrapper, sizeof (im->wrapper));

        r = VirtualProtect (&f->u1.Function, sizeof (f->u1.Function), o, &o);
        assert (r);
      }
    }
  }

  /* Make sure the library imports each function that we make fail.
   */
  for (size_t i = 0; i != FAULT_COUNT; ++i)
    assert (fault_imports[i].function != NULL);
}
