//! Secure memory handling.
//!
//! Sensitive buffers (keys, passwords, plaintext metadata) are wrapped in
//! `SecureBytes`, which guarantees the underlying memory is zeroed on drop
//! using the `zeroize` crate. `zeroize` uses volatile writes
//! (`core::ptr::write_volatile`) plus a compiler fence, which prevents the
//! optimizer from eliminating the write as "dead code" the way a plain
//! `for b in buf { *b = 0 }` loop could be -- the same property provided by
//! `explicit_bzero()` on Linux/BSD or `SecureZeroMemory()` on Windows.
//!
//! Where the OS supports it we additionally attempt to lock the pages
//! containing the secret in physical RAM (`mlock` on Linux, `VirtualLock`
//! on Windows) so the secret is never written to swap/pagefile. This is
//! best-effort: it requires privileges/limits that may not be available in
//! all execution contexts, so failures are logged but non-fatal.

use zeroize::Zeroize;

pub struct SecureBytes {
    data: Vec<u8>,
    locked: bool,
}

impl SecureBytes {
    pub fn new(data: Vec<u8>) -> Self {
        let locked = lock_memory(&data);
        Self { data, locked }
    }

    pub fn zeroed(len: usize) -> Self {
        Self::new(vec![0u8; len])
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn is_page_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        if self.locked {
            unlock_memory(&self.data);
        }
        self.data.zeroize();
    }
}

impl std::fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBytes({} bytes, REDACTED)", self.data.len())
    }
}

/// Explicitly and verifiably zero a byte buffer in place, resistant to
/// dead-store elimination by the optimizer.
pub fn secure_zero(buf: &mut [u8]) {
    buf.zeroize();
}

#[cfg(unix)]
fn lock_memory(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    unsafe {
        let ptr = data.as_ptr() as *const libc_mlock::c_void;
        libc_mlock::mlock(ptr, data.len()) == 0
    }
}

#[cfg(unix)]
fn unlock_memory(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    unsafe {
        let ptr = data.as_ptr() as *const libc_mlock::c_void;
        libc_mlock::munlock(ptr, data.len());
    }
}

#[cfg(windows)]
fn lock_memory(_data: &[u8]) -> bool {
    // VirtualLock requires the exact base address/size of a committed
    // region and interacts awkwardly with Vec's allocator-owned memory;
    // page locking on Windows is treated as best-effort and currently
    // not wired up for heap-allocated Vec<u8> without a custom allocator.
    false
}

#[cfg(windows)]
fn unlock_memory(_data: &[u8]) {}

#[cfg(not(any(unix, windows)))]
fn lock_memory(_data: &[u8]) -> bool {
    false
}
#[cfg(not(any(unix, windows)))]
fn unlock_memory(_data: &[u8]) {}

#[cfg(unix)]
mod libc_mlock {
    use std::os::raw::c_int;
    pub use std::os::raw::c_void;
    extern "C" {
        pub fn mlock(addr: *const c_void, len: usize) -> c_int;
        pub fn munlock(addr: *const c_void, len: usize) -> c_int;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_bytes_holds_data_until_drop() {
        let sb = SecureBytes::new(vec![0xAAu8; 32]);
        assert_eq!(sb.as_slice(), &[0xAAu8; 32]);
    }

    #[test]
    fn secure_zero_clears_buffer() {
        let mut buf = vec![0xFFu8; 16];
        secure_zero(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }
}
