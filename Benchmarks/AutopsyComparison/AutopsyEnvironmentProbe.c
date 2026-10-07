#include <jni.h>
#include <mach-o/dyld.h>
#include <crt_externs.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

/* Inspect addresses only. In particular, never dereference stack-backed
 * environment strings left behind by the old JNI initializer. */
JNIEXPORT jint JNICALL Java_AutopsyRepairProbe_environmentStackEntries
  (JNIEnv *env, jclass cls) {
    (void)env; (void)cls;
    pthread_t thread = pthread_self();
    uintptr_t upper = (uintptr_t)pthread_get_stackaddr_np(thread);
    uintptr_t lower = upper - pthread_get_stacksize_np(thread);
    char **entries = *_NSGetEnviron();
    jint count = 0;
    for (size_t i = 0; i < 4096 && entries[i] != NULL; i++) {
        uintptr_t address = (uintptr_t)entries[i];
        if (address >= lower && address < upper) count++;
    }
    return count;
}

/* Paths identify the library dyld actually loaded, rather than merely the
 * staged copy. No environment values or process memory are emitted. */
JNIEXPORT jobjectArray JNICALL Java_AutopsyRepairProbe_loadedTSKLibraries
  (JNIEnv *env, jclass cls) {
    (void)cls;
    const char *names[16];
    jsize count = 0;
    uint32_t image_count = _dyld_image_count();
    for (uint32_t i = 0; i < image_count && count < 16; i++) {
        const char *name = _dyld_get_image_name(i);
        const char *base = strrchr(name, '/');
        base = base == NULL ? name : base + 1;
        if (strstr(base, "libtsk") == base && strstr(base, ".dylib") != NULL) {
            names[count++] = name;
        }
    }
    jclass stringClass = (*env)->FindClass(env, "java/lang/String");
    jobjectArray result = (*env)->NewObjectArray(env, count, stringClass, NULL);
    for (jsize i = 0; i < count; i++) {
        jstring value = (*env)->NewStringUTF(env, names[i]);
        (*env)->SetObjectArrayElement(env, result, i, value);
        (*env)->DeleteLocalRef(env, value);
    }
    return result;
}
