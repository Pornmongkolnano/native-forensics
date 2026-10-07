#include <sqlite3.h>
#include <strings.h>

static inline int nf_sqlite_authorizer(void *context, int action,
        const char *first, const char *second, const char *database,
        const char *trigger) {
    (void)context; (void)database; (void)trigger;
    if (action == SQLITE_FUNCTION && second &&
            strcasecmp(second, "load_extension") == 0) return SQLITE_DENY;
    switch (action) {
        case SQLITE_SELECT: case SQLITE_READ: case SQLITE_FUNCTION:
            return SQLITE_OK;
        case SQLITE_PRAGMA:
            if (first && (strcasecmp(first, "quick_check") == 0 ||
                    strcasecmp(first, "table_info") == 0)) return SQLITE_OK;
            return SQLITE_DENY;
        default:
            return SQLITE_DENY;
    }
}

/* Keep varargs calls out of Swift and disable executable schema features. */
static inline int nf_sqlite_harden(sqlite3 *database) {
    int result = sqlite3_db_config(database, SQLITE_DBCONFIG_DEFENSIVE, 1, (int *)0);
    if (result != SQLITE_OK) return result;
    result = sqlite3_db_config(database, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, (int *)0);
    if (result != SQLITE_OK) return result;
    result = sqlite3_set_authorizer(database, nf_sqlite_authorizer, (void *)0);
    if (result != SQLITE_OK) return result;
    /* Apple's system dylib permanently omits extension loading. Its db_config
       option is unsupported too; only configure it when compiled in. */
    if (sqlite3_compileoption_used("OMIT_LOAD_EXTENSION")) return SQLITE_OK;
    return sqlite3_db_config(database, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, (int *)0);
}
