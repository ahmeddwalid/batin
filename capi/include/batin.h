/*
 * Batin C API
 *
 * Minimal C-callable surface over the Batin file-detection core.
 * Link against libbatin_capi (cdylib or staticlib).
 */
#ifndef BATIN_H
#define BATIN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Detect the file type of `data` (`len` bytes) and return a heap-allocated,
 * NUL-terminated JSON string describing the result. Free it with
 * batin_free_string. Returns NULL on allocation failure.
 */
char *batin_detect_json(const unsigned char *data, size_t len);

/* Free a string returned by batin_detect_json. */
void batin_free_string(char *ptr);

/* Return the library version as a static NUL-terminated string. */
const char *batin_version(void);

#ifdef __cplusplus
}
#endif

#endif /* BATIN_H */
