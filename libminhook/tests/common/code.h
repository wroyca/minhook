#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdint.h>
#include <string.h> /* memcpy(), memset() */

#undef NDEBUG
#include <assert.h>

/* Page of executable memory for machine code that a test writes. The page
 * is filled with int3 (CC), which the library takes for padding. It follows
 * a non-executable page of the same content, so that code at the start of
 * the page has padding above it that the library cannot use.
 */
#define CODE_PAGE_SIZE 0x1000

/* Allocate the page, copy the code, if any, to the offset, and return the
 * page's address.
 */
static uint8_t*
code_allocate (size_t offset, const uint8_t* code, size_t size)
{
  assert (offset + size <= CODE_PAGE_SIZE);

  uint8_t* p = (uint8_t*) VirtualAlloc (NULL,
                                        2 * CODE_PAGE_SIZE,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
  assert (p != NULL);

  memset (p, 0xCC, 2 * CODE_PAGE_SIZE);

  DWORD o;
  BOOL r = VirtualProtect (p, CODE_PAGE_SIZE, PAGE_READWRITE, &o);
  assert (r);

  p += CODE_PAGE_SIZE;

  if (size != 0)
    memcpy (p + offset, code, size);

  return p;
}

/* Free the page that code_allocate() returned.
 */
static void
code_free (uint8_t* p)
{
  BOOL r = VirtualFree (p - CODE_PAGE_SIZE, 0, MEM_RELEASE);
  assert (r);
}
