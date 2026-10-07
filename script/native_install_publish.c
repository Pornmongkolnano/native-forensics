/*
 * NativeForensics installation publisher.
 *
 * This original helper performs only a same-filesystem, exclusive directory
 * exchange. The caller prepares and validates the staged bundle, and owns its
 * cleanup. This helper never recursively removes an application or a backup.
 *
 * Build on macOS:
 *   clang -std=c11 -Wall -Wextra -Werror -O2 -mmacosx-version-min=14.0 \
 *     native_install_publish.c -o native-install-publish
 */

#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef RENAME_EXCL
#error "This helper requires macOS renameatx_np with RENAME_EXCL."
#endif

static const char *const app_name = "NativeForensics.app";
static const char *const install_lock_name = ".nativeforensics-install.lock";
static volatile sig_atomic_t interrupted_signal;

typedef struct {
    int parent_fd;
    char *absolute_input;
    char *leaf;
    struct stat parent_stat;
} AppPath;

typedef struct {
    int fd;
    int parent_fd; /* Borrowed from the destination AppPath. */
    char name[NAME_MAX + 1];
    struct stat identity;
    bool named;
    bool created_unverified;
} OwnedDirectory;

static char error_message[2048];

static void fail(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    (void)vsnprintf(error_message, sizeof(error_message), format, arguments);
    va_end(arguments);
}

static void fail_errno(const char *operation) {
    int saved_errno = errno;
    fail("%s: %s", operation, strerror(saved_errno));
}

static bool same_object(const struct stat *first, const struct stat *second) {
    return first->st_dev == second->st_dev && first->st_ino == second->st_ino;
}

static void close_path(AppPath *path) {
    if (path->parent_fd >= 0) {
        (void)close(path->parent_fd);
        path->parent_fd = -1;
    }
    free(path->absolute_input);
    free(path->leaf);
    path->absolute_input = NULL;
    path->leaf = NULL;
}

/* Every ancestor is opened relative to an already-open, no-follow directory.
 * Dot components are harmless; parent components are deliberately rejected. */
static bool resolve_path(const char *input, AppPath *result) {
    result->parent_fd = -1;
    if (input == NULL || input[0] == '\0') {
        fail("An application path must not be empty.");
        return false;
    }
    if (input[0] == '/') {
        result->absolute_input = strdup(input);
    } else {
        char *working_directory = getcwd(NULL, 0);
        if (working_directory == NULL) {
            fail_errno("Read the working directory");
            return false;
        }
        size_t length = strlen(working_directory) + strlen(input) + 2;
        result->absolute_input = malloc(length);
        if (result->absolute_input != NULL) {
            (void)snprintf(result->absolute_input, length, "%s/%s",
                           working_directory, input);
        }
        free(working_directory);
    }
    if (result->absolute_input == NULL) {
        fail("Out of memory while resolving an application path.");
        return false;
    }
    char *components = strdup(result->absolute_input);
    if (components == NULL) {
        fail("Out of memory while resolving path components.");
        return false;
    }
    int directory_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0) {
        fail_errno("Open the filesystem root");
        free(components);
        return false;
    }
    char *saved = NULL;
    char *pending = NULL;
    for (char *component = strtok_r(components, "/", &saved); component != NULL;
         component = strtok_r(NULL, "/", &saved)) {
        if (strcmp(component, ".") == 0) {
            continue;
        }
        if (strcmp(component, "..") == 0) {
            fail("Parent path components (..) are not permitted.");
            goto invalid;
        }
        if (strlen(component) > NAME_MAX) {
            fail("A path component exceeds the filesystem name limit.");
            goto invalid;
        }
        if (pending != NULL) {
            int next_fd = openat(directory_fd, pending,
                                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (next_fd < 0) {
                fail_errno("Open a real path ancestor without following symlinks");
                goto invalid;
            }
            (void)close(directory_fd);
            directory_fd = next_fd;
        }
        pending = component;
    }
    if (pending == NULL) {
        fail("The filesystem root is not an application path.");
        goto invalid;
    }
    result->leaf = strdup(pending);
    if (result->leaf == NULL) {
        fail("Out of memory while resolving the application name.");
        goto invalid;
    }
    if (fstat(directory_fd, &result->parent_stat) != 0) {
        fail_errno("Read the application parent identity");
        goto invalid;
    }
    result->parent_fd = directory_fd;
    free(components);
    return true;

invalid:
    (void)close(directory_fd);
    free(components);
    return false;
}

static bool parent_still_bound(const AppPath *path) {
    AppPath current = {.parent_fd = -1};
    bool resolved = resolve_path(path->absolute_input, &current);
    bool matches = resolved && same_object(&path->parent_stat, &current.parent_stat)
                   && strcmp(path->leaf, current.leaf) == 0;
    close_path(&current);
    if (resolved && !matches) {
        fail("An application path ancestor changed during installation.");
    }
    return matches;
}

static bool read_real_directory(const AppPath *path, struct stat *identity,
                                bool allow_missing, bool *exists) {
    if (fstatat(path->parent_fd, path->leaf, identity, AT_SYMLINK_NOFOLLOW) != 0) {
        if (allow_missing && errno == ENOENT) {
            *exists = false;
            return true;
        }
        fail_errno("Read the application directory identity");
        return false;
    }
    if (!S_ISDIR(identity->st_mode)) {
        fail("Application paths must be real directories, not files or symlinks.");
        return false;
    }
    *exists = true;
    return true;
}

/* Returns 1 if identity is this directory or an ancestor, 0 if unrelated,
 * and -1 on a filesystem error. No names or symlinks are followed. */
static int contains_ancestor(int directory_fd, const struct stat *identity) {
    int current_fd = fcntl(directory_fd, F_DUPFD_CLOEXEC, 3);
    if (current_fd < 0) {
        fail_errno("Duplicate a directory handle");
        return -1;
    }
    for (;;) {
        struct stat current;
        if (fstat(current_fd, &current) != 0) {
            fail_errno("Inspect an application ancestor");
            (void)close(current_fd);
            return -1;
        }
        if (same_object(&current, identity)) {
            (void)close(current_fd);
            return 1;
        }
        int parent_fd = openat(current_fd, "..",
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (parent_fd < 0) {
            fail_errno("Inspect an application parent directory");
            (void)close(current_fd);
            return -1;
        }
        struct stat parent;
        if (fstat(parent_fd, &parent) != 0) {
            fail_errno("Read an application parent directory identity");
            (void)close(current_fd);
            (void)close(parent_fd);
            return -1;
        }
        (void)close(current_fd);
        current_fd = parent_fd;
        if (same_object(&current, &parent)) {
            (void)close(current_fd);
            return 0;
        }
    }
}

static bool owned_entry_matches(const OwnedDirectory *directory) {
    struct stat named;
    return directory->named
           && fstatat(directory->parent_fd, directory->name, &named,
                      AT_SYMLINK_NOFOLLOW) == 0
           && S_ISDIR(named.st_mode) && same_object(&named, &directory->identity);
}

/* Remove only the exact owned directory, and only when it is empty. */
static bool remove_owned_empty(OwnedDirectory *directory) {
    if (!directory->named) {
        return true;
    }
    if (!owned_entry_matches(directory)) {
        return false;
    }
    if (unlinkat(directory->parent_fd, directory->name, AT_REMOVEDIR) != 0) {
        return false;
    }
    directory->named = false;
    return true;
}

static bool make_owned_directory(int parent_fd, const char *kind,
                                 OwnedDirectory *directory) {
    directory->parent_fd = parent_fd;
    directory->fd = -1;
    for (unsigned int attempt = 0; attempt < 32; ++attempt) {
        unsigned char entropy[16];
        char suffix[33];
        arc4random_buf(entropy, sizeof(entropy));
        for (size_t index = 0; index < sizeof(entropy); ++index) {
            (void)snprintf(suffix + index * 2, 3, "%02x", entropy[index]);
        }
        (void)snprintf(directory->name, sizeof(directory->name),
                       ".nativeforensics-install-%s.%s", kind, suffix);
        if (mkdirat(parent_fd, directory->name, 0700) != 0) {
            if (errno == EEXIST) {
                continue;
            }
            fail_errno("Create an owned installation directory");
            return false;
        }
        /* A failed identity read must never authorize deleting the name. Keep
         * its candidate path in the failure receipt for manual recovery. */
        directory->created_unverified = true;
        struct stat named;
        if (fstatat(parent_fd, directory->name, &named, AT_SYMLINK_NOFOLLOW) != 0
            || !S_ISDIR(named.st_mode) || named.st_uid != geteuid()) {
            fail("The newly created installation directory changed ownership or type.");
            return false;
        }
        directory->identity = named;
        directory->named = true;
        directory->created_unverified = false;
        directory->fd = openat(parent_fd, directory->name,
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat opened;
        if (directory->fd < 0 || fstat(directory->fd, &opened) != 0
            || !same_object(&opened, &named) || !owned_entry_matches(directory)) {
            fail("The newly created installation directory changed while opening it.");
            (void)remove_owned_empty(directory);
            return false;
        }
        return true;
    }
    fail("Unable to choose an unused installation directory name.");
    return false;
}

/* Claim the stable lock name by exclusively renaming an already-open owned
 * directory. We never open or remove an existing installer's lock directory. */
static bool acquire_lock(int parent_fd, OwnedDirectory *lock) {
    if (!make_owned_directory(parent_fd, "lock-claim", lock)) {
        return false;
    }
    if (renameatx_np(parent_fd, lock->name, parent_fd, install_lock_name,
                     RENAME_EXCL) != 0) {
        if (errno == EEXIST || errno == ENOTEMPTY) {
            fail("Another installation lock exists. Close the other installer; "
                 "a lock left by an interrupted installation must be reviewed manually.");
        } else {
            fail_errno("Claim the exclusive installation lock");
        }
        (void)remove_owned_empty(lock);
        return false;
    }
    (void)snprintf(lock->name, sizeof(lock->name), "%s", install_lock_name);
    if (!owned_entry_matches(lock)) {
        fail("The installation lock changed during acquisition.");
        return false;
    }
    return true;
}

static void interrupt_handler(int signal_number) {
    interrupted_signal = signal_number;
}

static bool observe_interrupt(void) {
    if (interrupted_signal == 0) {
        return false;
    }
    fail("Installation interrupted by signal %d before publication.",
         (int)interrupted_signal);
    return true;
}

static void json_string(const char *string) {
    if (string == NULL) {
        (void)fputs("null", stdout);
        return;
    }
    (void)fputc('"', stdout);
    for (const unsigned char *cursor = (const unsigned char *)string;
         *cursor != '\0'; ++cursor) {
        switch (*cursor) {
            case '"': (void)fputs("\\\"", stdout); break;
            case '\\': (void)fputs("\\\\", stdout); break;
            case '\n': (void)fputs("\\n", stdout); break;
            case '\r': (void)fputs("\\r", stdout); break;
            case '\t': (void)fputs("\\t", stdout); break;
            default:
                if (*cursor < 0x20) {
                    (void)fprintf(stdout, "\\u%04x", *cursor);
                } else {
                    (void)fputc(*cursor, stdout);
                }
        }
    }
    (void)fputc('"', stdout);
}

static char *path_for_entry(int parent_fd, const char *leaf) {
    if (parent_fd < 0 || leaf == NULL) {
        return NULL;
    }
    char parent[PATH_MAX];
    if (fcntl(parent_fd, F_GETPATH, parent) != 0) {
        return NULL;
    }
    size_t length = strlen(parent) + strlen(leaf) + 2;
    char *result = malloc(length);
    if (result != NULL) {
        (void)snprintf(result, length, "%s%s%s", parent,
                       strcmp(parent, "/") == 0 ? "" : "/", leaf);
    }
    return result;
}

int main(int argc, char **argv) {
    AppPath stage = {.parent_fd = -1};
    AppPath destination = {.parent_fd = -1};
    OwnedDirectory lock = {.fd = -1, .parent_fd = -1};
    OwnedDirectory backup = {.fd = -1, .parent_fd = -1};
    bool replace = argc == 4 && strcmp(argv[3], "--replace") == 0;
    bool installed = false;
    bool old_app_saved = false;
    bool success = false;
    bool destination_exists = false;
    struct stat stage_identity;
    struct stat old_identity;
    int stage_fd = -1;
    int destination_fd = -1;
    int exit_status = 1;

    if ((argc != 3 && argc != 4) || (argc == 4 && !replace)) {
        fail("Usage: native-install-publish STAGED_APP DESTINATION_APP [--replace]");
        exit_status = 64;
        goto finish;
    }
    (void)umask(077);
    struct sigaction interrupt_action;
    memset(&interrupt_action, 0, sizeof(interrupt_action));
    interrupt_action.sa_handler = interrupt_handler;
    interrupt_action.sa_flags = SA_RESTART;
    (void)sigemptyset(&interrupt_action.sa_mask);
    if (sigaction(SIGINT, &interrupt_action, NULL) != 0
        || sigaction(SIGTERM, &interrupt_action, NULL) != 0
        || sigaction(SIGHUP, &interrupt_action, NULL) != 0) {
        fail_errno("Install interruption handlers");
        goto finish;
    }
    if (!resolve_path(argv[1], &stage) || !resolve_path(argv[2], &destination)) {
        goto finish;
    }
    if (strcmp(destination.leaf, app_name) != 0) {
        fail("The destination application must be named NativeForensics.app.");
        goto finish;
    }
    if (stage.parent_stat.st_uid != geteuid()
        || destination.parent_stat.st_uid != geteuid()) {
        fail("The staged and destination parent directories must be owned by the current user.");
        goto finish;
    }
    if (faccessat(stage.parent_fd, ".", W_OK | X_OK, AT_EACCESS) != 0
        || faccessat(destination.parent_fd, ".", W_OK | X_OK, AT_EACCESS) != 0) {
        fail_errno("Access the application parent directories for publication");
        goto finish;
    }
    bool stage_exists = false;
    if (!read_real_directory(&stage, &stage_identity, false, &stage_exists)) {
        goto finish;
    }
    if (stage_identity.st_uid != geteuid()) {
        fail("The staged application must be owned by the current user.");
        goto finish;
    }
    stage_fd = openat(stage.parent_fd, stage.leaf,
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat stage_opened;
    if (stage_fd < 0 || fstat(stage_fd, &stage_opened) != 0
        || !same_object(&stage_opened, &stage_identity)) {
        fail("The staged application changed while opening it.");
        goto finish;
    }
    if (stage_identity.st_dev != destination.parent_stat.st_dev) {
        fail("The staged application and destination parent must use the same filesystem.");
        goto finish;
    }
    int overlap = contains_ancestor(destination.parent_fd, &stage_identity);
    if (overlap != 0) {
        if (overlap > 0) {
            fail("The destination must not be inside the staged application.");
        }
        goto finish;
    }
    if (!acquire_lock(destination.parent_fd, &lock)) {
        goto finish;
    }
    if (!parent_still_bound(&stage) || !parent_still_bound(&destination)
        || !owned_entry_matches(&lock) || observe_interrupt()) {
        if (error_message[0] == '\0') {
            fail("The installation lock changed before publication.");
        }
        goto finish;
    }
    if (!read_real_directory(&destination, &old_identity, true, &destination_exists)) {
        goto finish;
    }
    if (destination_exists) {
        if (old_identity.st_uid != geteuid()) {
            fail("The existing application must be owned by the current user.");
            goto finish;
        }
        if (!replace) {
            fail("NativeForensics.app already exists. Use --replace to retain it as a backup.");
            goto finish;
        }
        if (same_object(&stage_identity, &old_identity)) {
            fail("The staged and destination applications must be distinct directories.");
            goto finish;
        }
        destination_fd = openat(destination.parent_fd, destination.leaf,
                                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat destination_opened;
        if (destination_fd < 0 || fstat(destination_fd, &destination_opened) != 0
            || !same_object(&destination_opened, &old_identity)) {
            fail("The existing application changed while opening it.");
            goto finish;
        }
        overlap = contains_ancestor(stage.parent_fd, &old_identity);
        if (overlap != 0) {
            if (overlap > 0) {
                fail("The staged application must not be inside the existing application.");
            }
            goto finish;
        }
        if (!make_owned_directory(destination.parent_fd, "backup", &backup)) {
            goto finish;
        }
    }
    struct stat stage_now;
    bool exists_now = false;
    if (!parent_still_bound(&stage) || !parent_still_bound(&destination)
        || !read_real_directory(&stage, &stage_now, false, &exists_now)
        || !same_object(&stage_identity, &stage_now) || !owned_entry_matches(&lock)
        || observe_interrupt()) {
        if (error_message[0] == '\0') {
            fail("The staged application or installation lock changed before publication.");
        }
        goto finish;
    }
    if (destination_exists) {
        struct stat destination_now;
        if (!read_real_directory(&destination, &destination_now, false, &exists_now)
            || !same_object(&old_identity, &destination_now)
            || !owned_entry_matches(&backup)) {
            if (error_message[0] == '\0') {
                fail("The existing application or backup directory changed before publication.");
            }
            goto finish;
        }
        if (renameatx_np(destination.parent_fd, destination.leaf, backup.fd,
                         app_name, RENAME_EXCL) != 0) {
            fail_errno("Preserve the existing application in its owned backup directory");
            goto finish;
        }
        old_app_saved = true;
        struct stat saved;
        if (fstatat(backup.fd, app_name, &saved, AT_SYMLINK_NOFOLLOW) != 0
            || !same_object(&old_identity, &saved)) {
            fail("The existing application changed during backup publication.");
            goto rollback;
        }
    }
    if (!parent_still_bound(&stage) || !parent_still_bound(&destination)
        || !owned_entry_matches(&lock)
        || !read_real_directory(&stage, &stage_now, false, &exists_now)
        || !same_object(&stage_identity, &stage_now) || observe_interrupt()) {
        if (error_message[0] == '\0') {
            fail("The staged application or installation lock changed before publication.");
        }
        goto rollback;
    }
    if (renameatx_np(stage.parent_fd, stage.leaf, destination.parent_fd,
                     destination.leaf, RENAME_EXCL) != 0) {
        fail_errno("Exclusively publish the staged application");
        goto rollback;
    }
    struct stat published;
    if (fstatat(destination.parent_fd, destination.leaf, &published,
                AT_SYMLINK_NOFOLLOW) != 0 || !same_object(&stage_identity, &published)) {
        /* Do not remove or overwrite the unexpected occupant. The old bundle,
         * if any, remains in the backup for manual recovery. */
        fail("The destination changed during publication; any old application remains in its backup.");
        goto finish;
    }
    installed = true;
    success = true;
    goto finish;

rollback:
    if (old_app_saved) {
        char original_error[sizeof(error_message)];
        (void)snprintf(original_error, sizeof(original_error), "%s", error_message);
        if (renameatx_np(backup.fd, app_name, destination.parent_fd,
                         destination.leaf, RENAME_EXCL) == 0) {
            old_app_saved = false;
        } else {
            int rollback_errno = errno;
            fail("%.1400s Rollback could not restore the old application: %s. "
                 "The old application is retained at backup_path.",
                 original_error, strerror(rollback_errno));
        }
    }

finish:
    if (!old_app_saved && !remove_owned_empty(&backup)) {
        success = false;
        if (error_message[0] == '\0') {
            fail("An owned empty backup directory could not be removed safely.");
        }
    }
    if (!remove_owned_empty(&lock)) {
        success = false;
        if (error_message[0] == '\0') {
            fail("The installation lock could not be removed safely; review lock_path.");
        }
    }
    if (success) {
        exit_status = 0;
    }
    char *destination_path = path_for_entry(destination.parent_fd, destination.leaf);
    char *backup_path = old_app_saved ? path_for_entry(backup.fd, app_name) : NULL;
    char *lock_path = lock.named ? path_for_entry(lock.parent_fd, lock.name) : NULL;
    char *unverified_path = backup.created_unverified
        ? path_for_entry(backup.parent_fd, backup.name)
        : (lock.created_unverified ? path_for_entry(lock.parent_fd, lock.name) : NULL);
    (void)fputs("{\"status\":", stdout);
    json_string(success ? "installed" : "failed");
    (void)fprintf(stdout, ",\"installed\":%s,\"destination_path\":",
                  installed ? "true" : "false");
    json_string(destination_path);
    (void)fputs(",\"backup_path\":", stdout);
    json_string(backup_path);
    (void)fputs(",\"lock_path\":", stdout);
    json_string(lock_path);
    (void)fputs(",\"unverified_directory_path\":", stdout);
    json_string(unverified_path);
    (void)fputs(",\"error\":", stdout);
    json_string(error_message[0] == '\0' ? NULL : error_message);
    (void)fputs("}\n", stdout);
    if (fflush(stdout) != 0 || ferror(stdout)) {
        (void)fputs("The installation result could not be delivered. "
                    "Review the destination and any retained backup before retrying.\n", stderr);
        exit_status = 1;
    }
    free(destination_path);
    free(backup_path);
    free(lock_path);
    free(unverified_path);
    if (stage_fd >= 0) {
        (void)close(stage_fd);
    }
    if (destination_fd >= 0) {
        (void)close(destination_fd);
    }
    if (backup.fd >= 0) {
        (void)close(backup.fd);
    }
    if (lock.fd >= 0) {
        (void)close(lock.fd);
    }
    close_path(&stage);
    close_path(&destination);
    return exit_status;
}
