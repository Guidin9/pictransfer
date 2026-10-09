//! JNI entry point that gives iroh (DNS resolver, network monitor) access to
//! the JavaVM and the application Context via `ndk-context`. Kotlin calls
//! `Core.initAndroid(applicationContext)` once, before opening the core;
//! without it the first endpoint bind aborts the process.
#![allow(unsafe_code)]

use std::sync::Once;

use jni_sys::{JNIEnv, JavaVM, jobject};

static INIT: Once = Once::new();

/// `io.github.guidin9.warpshot.Core.initAndroid(Context)`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_guidin9_warpshot_Core_initAndroid(
    env: *mut JNIEnv,
    _this: jobject,
    context: jobject,
) {
    if env.is_null() || context.is_null() {
        return;
    }
    INIT.call_once(|| {
        // SAFETY: `env` is the valid JNIEnv of the calling thread (JNI contract);
        // the global reference keeps the application Context alive for the
        // process lifetime, as ndk-context requires.
        unsafe {
            let Some(table) = (*env).as_ref() else { return };
            let (Some(get_vm), Some(new_global)) = (table.GetJavaVM, table.NewGlobalRef) else {
                return;
            };
            let mut vm: *mut JavaVM = std::ptr::null_mut();
            if get_vm(env, &mut vm) != 0 || vm.is_null() {
                return;
            }
            let ctx = new_global(env, context);
            if ctx.is_null() {
                return;
            }
            ndk_context::initialize_android_context(vm.cast(), ctx.cast());
        }
    });
}
