use libc::{c_char, c_void, size_t};
use std::ffi::{CStr, CString};
use std::ptr;
use std::slice;

// ── C Struct Bindings ──

#[repr(C)]
pub struct CHiggaionKey {
    pub pkey: *mut c_void,
}

// ── External FFI Declarations ──

#[link(name = "pqc_crypto")]
#[link(name = "crypto")]
extern "C" {
    fn higgaion_key_init(key: *mut CHiggaionKey);
    fn higgaion_key_free(key: *mut CHiggaionKey);
    #[link_name = "generate_keypair"]
    fn c_generate_keypair(key: *mut CHiggaionKey, alg_name: *const c_char);
    
    fn pqc_sign(
        signature: *mut *mut u8,
        sig_len: *mut size_t,
        message: *const u8,
        msg_len: size_t,
        domain: *const c_char,
        sk: *const CHiggaionKey,
    );

    fn pqc_verify(
        message: *const u8,
        msg_len: size_t,
        signature: *const u8,
        sig_len: size_t,
        domain: *const c_char,
        pk: *const CHiggaionKey,
    ) -> bool;
}

// ── Safe Rust Wrappers ──

#[derive(Debug)]
pub enum HiggaionError {
    KeyGenerationFailed,
    SigningFailed,
    InvalidParameter,
}

/// A mathematical isolation bound holding the private OpenSSL PQC key data.
pub struct PrivateKey {
    inner: CHiggaionKey,
    owns_memory: bool,
}

/// A mathematical isolation bound holding the public OpenSSL verification data.
pub struct PublicKey {
    inner: CHiggaionKey,
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        if self.owns_memory && !self.inner.pkey.is_null() {
            unsafe {
                // Free the underlying OpenSSL memory reliably on Rust teardown
                higgaion_key_free(&mut self.inner);
            }
            self.inner.pkey = ptr::null_mut();
        }
    }
}

impl PrivateKey {
    pub fn sign(&self, message: &[u8], domain: &str) -> Result<Vec<u8>, HiggaionError> {
        if self.inner.pkey.is_null() {
            return Err(HiggaionError::InvalidParameter);
        }

        let c_domain = CString::new(domain).map_err(|_| HiggaionError::InvalidParameter)?;
        
        let c_msg_ptr = if message.is_empty() {
            ptr::null()
        } else {
            message.as_ptr()
        };
        let c_msg_len = message.len() as size_t;

        let mut c_sig_ptr: *mut u8 = ptr::null_mut();
        let mut c_sig_len: size_t = 0;

        unsafe {
            pqc_sign(
                &mut c_sig_ptr,
                &mut c_sig_len,
                c_msg_ptr,
                c_msg_len,
                c_domain.as_ptr(),
                &self.inner,
            );
        }

        if c_sig_ptr.is_null() || c_sig_len == 0 {
            return Err(HiggaionError::SigningFailed);
        }

        let sig_bytes = unsafe {
            // Reconstruct the Rust Vec from the raw C-heap slice
            let slice = slice::from_raw_parts(c_sig_ptr, c_sig_len);
            let vec = slice.to_vec();
            
            // Explicitly route destruction of the C-malloc'd array to libc
            libc::free(c_sig_ptr as *mut c_void);
            
            vec
        };

        Ok(sig_bytes)
    }
}

impl PublicKey {
    pub fn verify(&self, message: &[u8], signature: &[u8], domain: &str) -> bool {
        if self.inner.pkey.is_null() || signature.is_empty() {
            return false;
        }

        let c_domain = match CString::new(domain) {
            Ok(d) => d,
            Err(_) => return false,
        };

        let c_msg_ptr = if message.is_empty() {
            ptr::null()
        } else {
            message.as_ptr()
        };
        let c_msg_len = message.len() as size_t;

        unsafe {
            pqc_verify(
                c_msg_ptr,
                c_msg_len,
                signature.as_ptr(),
                signature.len() as size_t,
                c_domain.as_ptr(),
                &self.inner,
            )
        }
    }
}

/// Generates a perfectly integrated OpenSSL Post-Quantum keypair and hands ownership
/// perfectly to the Rust Memory manager.
pub fn generate_keypair(alg_name: &str) -> Result<(PrivateKey, PublicKey), HiggaionError> {
    let mut priv_inner = CHiggaionKey { pkey: ptr::null_mut() };
    let mut pub_inner = CHiggaionKey { pkey: ptr::null_mut() };

    unsafe {
        higgaion_key_init(&mut priv_inner);
        higgaion_key_init(&mut pub_inner);
    }

    let c_alg_name = CString::new(alg_name).map_err(|_| HiggaionError::InvalidParameter)?;

    unsafe {
        c_generate_keypair(&mut priv_inner, c_alg_name.as_ptr());
    }

    if priv_inner.pkey.is_null() {
        return Err(HiggaionError::KeyGenerationFailed);
    }

    // Hand the combined EVP_PKEY reference seamlessly into the PublicKey struct
    pub_inner.pkey = priv_inner.pkey;

    let priv_key = PrivateKey {
        inner: priv_inner,
        owns_memory: true,
    };
    
    let pub_key = PublicKey {
        inner: pub_inner,
    };

    Ok((priv_key, pub_key))
}
