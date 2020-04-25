/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "home-util.c"
#include "fuzz.h"
#include "util.h"


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free_ char *str = NULL, *ret1 = NULL, *ret2 = NULL;

        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        str = memdup_suffix0(data, size);

        (void) suitable_user_name(str);
        (void) suitable_realm(str);
        (void) suitable_image_path(str);
        (void) split_user_name_realm(str, &ret1, &ret2);

        return 0;
}
