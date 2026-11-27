//! Native backend for curve25519-java.
//!
//! Exposes X25519 / XEdDSA / VXEdDSA to the JVM through JNI static methods of
//! `org.whispersystems.curve25519.NativeCurve25519`. All entry points return `0` on success,
//! [`ERR_CRYPTO`] when an operation fails (e.g. an invalid signature) and [`ERR_ARGUMENT`]
//! for null or too-short arrays. They never panic across the FFI boundary for valid JNI
//! input, and the release profile aborts instead of unwinding.

// The `Java_*` exports are only called by the JVM, which guarantees a valid `JNIEnv` and
// `byte[]` references (or null, which is checked); no further safety contract applies.
#![allow(clippy::missing_safety_doc)]

pub mod curve;
mod fe;

use core::ptr;

use jni_sys::{jbyte, jbyteArray, jclass, jint, jsize, jstring, JNIEnv, JNI_ABORT};
use zeroize::Zeroize;

const OK: jint = 0;
const ERR_CRYPTO: jint = -1;
const ERR_ARGUMENT: jint = -2;

type Env = *mut JNIEnv;

/// # Safety
/// `env` must be the valid `JNIEnv` of the current thread and `arr` null or a live `byte[]`.
unsafe fn array_len(env: Env, arr: jbyteArray) -> Option<usize> {
    if arr.is_null() {
        return None;
    }
    let len = unsafe { ((**env).v1_1.GetArrayLength)(env, arr) };
    usize::try_from(len).ok()
}

/// Copies the first `N` bytes of a Java array. Fails if it is null or shorter than `N`.
///
/// # Safety
/// See [`array_len`].
unsafe fn read<const N: usize>(env: Env, arr: jbyteArray) -> Option<[u8; N]> {
    if unsafe { array_len(env, arr) }? < N {
        return None;
    }
    let mut out = [0u8; N];
    unsafe {
        ((**env).v1_1.GetByteArrayRegion)(env, arr, 0, N as jsize, out.as_mut_ptr() as *mut jbyte)
    };
    Some(out)
}

/// Copies `data` into the start of a Java array. Fails if it is null or too short.
///
/// # Safety
/// See [`array_len`].
unsafe fn write(env: Env, arr: jbyteArray, data: &[u8]) -> bool {
    match unsafe { array_len(env, arr) } {
        Some(len) if len >= data.len() => {
            unsafe {
                ((**env).v1_1.SetByteArrayRegion)(
                    env,
                    arr,
                    0,
                    data.len() as jsize,
                    data.as_ptr() as *const jbyte,
                )
            };
            true
        }
        _ => false,
    }
}

/// Runs `f` over the contents of a Java `byte[]` without copying it
/// (`GetPrimitiveArrayCritical`). No JNI calls may be made inside `f`.
///
/// # Safety
/// See [`array_len`].
unsafe fn with_message<R>(env: Env, arr: jbyteArray, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
    let len = unsafe { array_len(env, arr) }?;
    if len == 0 {
        return Some(f(&[]));
    }
    let data = unsafe { ((**env).v1_2.GetPrimitiveArrayCritical)(env, arr, ptr::null_mut()) };
    if data.is_null() {
        return None;
    }
    let result = f(unsafe { core::slice::from_raw_parts(data as *const u8, len) });
    unsafe { ((**env).v1_2.ReleasePrimitiveArrayCritical)(env, arr, data, JNI_ABORT) };
    Some(result)
}

fn status(ok: bool) -> jint {
    if ok { OK } else { ERR_ARGUMENT }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_whispersystems_curve25519_NativeCurve25519_smokeCheck(
    _env: Env,
    _class: jclass,
    dummy: jint,
) -> jint {
    dummy
}

/// Describes the hardware acceleration selected at runtime, e.g. `"curve=avx2 sha512=avx2"`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_whispersystems_curve25519_NativeCurve25519_backend(
    env: Env,
    _class: jclass,
) -> jstring {
    let info = backend_info();
    unsafe { ((**env).v1_1.NewStringUTF)(env, info.as_ptr()) }
}

/// Hardware acceleration in use, mirroring the runtime dispatch of curve25519-dalek and sha2.
pub fn backend_info() -> &'static core::ffi::CStr {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        cpufeatures::new!(cpu_ifma, "avx512ifma", "avx512vl");
        cpufeatures::new!(cpu_avx2, "avx2");
        cpufeatures::new!(cpu_sha512, "avx2", "bmi1", "bmi2");
        let ifma = cfg!(curve25519_dalek_backend = "avx512") && cpu_ifma::get();
        let avx2 = cfg!(all(target_arch = "x86_64", target_pointer_width = "64")) && cpu_avx2::get();
        match (ifma, avx2, cpu_sha512::get()) {
            (true, _, true) => c"curve=avx512ifma sha512=avx2",
            (true, _, false) => c"curve=avx512ifma sha512=soft",
            (false, true, true) => c"curve=avx2 sha512=avx2",
            (false, true, false) => c"curve=avx2 sha512=soft",
            (false, false, true) => c"curve=serial sha512=avx2",
            (false, false, false) => c"curve=serial sha512=soft",
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        cpufeatures::new!(cpu_sha3, "sha3");
        if cpu_sha3::get() { c"curve=serial sha512=armv8-sha512" } else { c"curve=serial sha512=soft" }
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        c"curve=serial sha512=soft"
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_whispersystems_curve25519_NativeCurve25519_generatePublicKey(
    env: Env,
    _class: jclass,
    public_key_out: jbyteArray,
    private_key: jbyteArray,
) -> jint {
    let Some(mut sk) = (unsafe { read::<32>(env, private_key) }) else {
        return ERR_ARGUMENT;
    };
    let pk = curve::public_key(&sk);
    sk.zeroize();
    status(unsafe { write(env, public_key_out, &pk) })
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_whispersystems_curve25519_NativeCurve25519_calculateAgreement(
    env: Env,
    _class: jclass,
    shared_key_out: jbyteArray,
    private_key: jbyteArray,
    public_key: jbyteArray,
) -> jint {
    let (Some(mut sk), Some(pk)) =
        (unsafe { read::<32>(env, private_key) }, unsafe { read::<32>(env, public_key) })
    else {
        return ERR_ARGUMENT;
    };
    let mut shared = curve::x25519(&sk, &pk);
    sk.zeroize();
    let ok = unsafe { write(env, shared_key_out, &shared) };
    shared.zeroize();
    status(ok)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_whispersystems_curve25519_NativeCurve25519_calculateSignature(
    env: Env,
    _class: jclass,
    signature_out: jbyteArray,
    random: jbyteArray,
    private_key: jbyteArray,
    message: jbyteArray,
) -> jint {
    let (Some(mut sk), Some(mut z)) =
        (unsafe { read::<32>(env, private_key) }, unsafe { read::<64>(env, random) })
    else {
        return ERR_ARGUMENT;
    };
    let sig = unsafe { with_message(env, message, |m| curve::xeddsa_sign(&sk, m, &z)) };
    sk.zeroize();
    z.zeroize();
    match sig {
        Some(sig) => status(unsafe { write(env, signature_out, &sig) }),
        None => ERR_ARGUMENT,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_whispersystems_curve25519_NativeCurve25519_verifySignature(
    env: Env,
    _class: jclass,
    public_key: jbyteArray,
    message: jbyteArray,
    signature: jbyteArray,
) -> jint {
    let (Some(pk), Some(sig)) =
        (unsafe { read::<32>(env, public_key) }, unsafe { read::<64>(env, signature) })
    else {
        return ERR_ARGUMENT;
    };
    match unsafe { with_message(env, message, |m| curve::xeddsa_verify(&pk, m, &sig)) } {
        Some(true) => OK,
        Some(false) => ERR_CRYPTO,
        None => ERR_ARGUMENT,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_whispersystems_curve25519_NativeCurve25519_calculateVrfSignature(
    env: Env,
    _class: jclass,
    signature_out: jbyteArray,
    random: jbyteArray,
    private_key: jbyteArray,
    message: jbyteArray,
) -> jint {
    let (Some(mut sk), Some(mut z)) =
        (unsafe { read::<32>(env, private_key) }, unsafe { read::<32>(env, random) })
    else {
        return ERR_ARGUMENT;
    };
    let sig = unsafe { with_message(env, message, |m| curve::vxeddsa_sign(&sk, m, &z)) };
    sk.zeroize();
    z.zeroize();
    match sig {
        Some(Some(sig)) => status(unsafe { write(env, signature_out, &sig) }),
        Some(None) => ERR_CRYPTO,
        None => ERR_ARGUMENT,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_org_whispersystems_curve25519_NativeCurve25519_verifyVrfSignature(
    env: Env,
    _class: jclass,
    vrf_out: jbyteArray,
    public_key: jbyteArray,
    message: jbyteArray,
    signature: jbyteArray,
) -> jint {
    let (Some(pk), Some(sig)) =
        (unsafe { read::<32>(env, public_key) }, unsafe { read::<96>(env, signature) })
    else {
        return ERR_ARGUMENT;
    };
    match unsafe { with_message(env, message, |m| curve::vxeddsa_verify(&pk, m, &sig)) } {
        Some(Some(vrf)) => status(unsafe { write(env, vrf_out, &vrf) }),
        Some(None) => ERR_CRYPTO,
        None => ERR_ARGUMENT,
    }
}
