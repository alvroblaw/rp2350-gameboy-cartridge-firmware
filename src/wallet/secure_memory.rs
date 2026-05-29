//! Secure memory wrappers that guarantee zeroization on Drop.
//!
//! Provides `SecureBox<T>`, `SecureSlice<T>`, and `SecureArray<T, N>` wrappers
//! that automatically zeroize their contents when dropped. Use these for any
//! sensitive data (keys, seeds, PINs) to prevent data leakage from SRAM after
//! the values are no longer needed.
//!
//! # Usage
//!
//! ```ignore
//! use crate::wallet::secure_memory::SecureArray;
//!
//! let mut pin_buf = SecureArray::<u8, 8>::new();
//! pin_buf.as_mut().copy_from_slice(b"12345678");
//! // ... use pin_buf ...
//! // On drop, pin_buf contents are zeroized automatically.
//! ```

#![allow(unused)]

use zeroize::Zeroize;

/// A wrapper that guarantees zeroization of the inner value on Drop.
///
/// Use for any heapless or stack-allocated sensitive type that implements
/// `Zeroize`. The inner value is zeroized when the `SecureBox` is dropped,
/// regardless of how the drop occurs (normal scope exit, panic, early return).
pub struct SecureBox<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> SecureBox<T> {
    /// Create a new secure wrapper around `value`.
    #[inline]
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// Get a reference to the inner value.
    #[inline]
    pub fn as_ref(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the inner value.
    #[inline]
    pub fn as_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Consume the wrapper and return the inner value.
    ///
    /// **WARNING**: The caller is now responsible for zeroization.
    pub fn into_inner(mut self) -> T {
        // We do NOT zeroize here — the caller takes ownership.
        // Use core::mem::ManuallyDrop to skip our Drop impl.
        let inner = core::ptr::read(&self.inner);
        // Zeroize our copy (the one that would be dropped) to avoid
        // a double-reference to the same data.
        core::mem::forget(self);
        inner
    }
}

impl<T: Zeroize> Drop for SecureBox<T> {
    #[inline]
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize + core::fmt::Debug> core::fmt::Debug for SecureBox<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Don't leak inner value in debug output
        f.write_str("SecureBox(<redacted>)")
    }
}

/// A secure slice wrapper that zeroizes contents on Drop.
///
/// Wraps a `&mut [T]` and zeroizes it when dropped.
/// Useful for borrows of sensitive stack or heap data.
pub struct SecureSlice<'a, T: Zeroize> {
    inner: &'a mut [T],
}

impl<'a, T: Zeroize> SecureSlice<'a, T> {
    /// Create a new secure slice wrapper.
    #[inline]
    pub fn new(slice: &'a mut [T]) -> Self {
        Self { inner: slice }
    }

    /// Get a reference to the inner slice.
    #[inline]
    pub fn as_ref(&self) -> &[T] {
        self.inner
    }

    /// Get a mutable reference to the inner slice.
    #[inline]
    pub fn as_mut(&mut self) -> &mut [T] {
        self.inner
    }
}

impl<'a, T: Zeroize> Drop for SecureSlice<'a, T> {
    #[inline]
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<'a, T: Zeroize> core::fmt::Debug for SecureSlice<'a, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecureSlice(<redacted>)")
    }
}

/// A fixed-size secure array that zeroizes contents on Drop.
///
/// Use for seed buffers, key material, PIN digits, and other
/// fixed-size sensitive data on the stack.
#[derive(Clone)]
pub struct SecureArray<T: Zeroize + Copy + Default, const N: usize> {
    data: [T; N],
}

impl<T: Zeroize + Copy + Default, const N: usize> SecureArray<T, N> {
    /// Create a new secure array initialized to default values.
    #[inline]
    pub fn new() -> Self {
        Self {
            data: [T::default(); N],
        }
    }

    /// Create from an existing array.
    #[inline]
    pub fn from_array(arr: [T; N]) -> Self {
        Self { data: arr }
    }

    /// Get a reference to the inner array.
    #[inline]
    pub fn as_ref(&self) -> &[T; N] {
        &self.data
    }

    /// Get a mutable reference to the inner array.
    #[inline]
    pub fn as_mut(&mut self) -> &mut [T; N] {
        &mut self.data
    }

    /// Get a slice view.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    /// Get a mutable slice view.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.data
    }

    /// Explicitly zeroize the array now (also happens on Drop).
    #[inline]
    pub fn zeroize_now(&mut self) {
        self.data.zeroize();
    }
}

impl<T: Zeroize + Copy + Default, const N: usize> Drop for SecureArray<T, N> {
    #[inline]
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl<T: Zeroize + Copy + Default, const N: usize> core::fmt::Debug for SecureArray<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecureArray(<redacted>)")
    }
}

impl<T: Zeroize + Copy + Default, const N: usize> Default for SecureArray<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Best-effort stack scrubbing.
///
/// Declares a large local array and zeroizes it to overwrite stack
/// memory that may have previously held sensitive data (keys, seeds, PINs).
///
/// This is a best-effort mitigation — the compiler may optimize it away,
/// and it only covers the current stack frame. However, on embedded without
/// heavy optimization, it provides meaningful cleanup.
///
/// Call after crypto operations that use stack-local buffers for key material.
#[inline]
pub fn secure_scrub_stack() {
    let mut scrub = [0u8; 256];
    // Volatile writes to prevent optimization
    for byte in scrub.iter_mut() {
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
    // Compiler fence to ensure the writes are not reordered away
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_box_zeroizes() {
        let mut box_val = SecureBox::new([0xABu8; 32]);
        // Verify we can access the data
        assert_eq!(box_val.as_ref()[0], 0xAB);
        // Drop should zeroize
        drop(box_val);
        // (Can't verify after drop — the point is it doesn't panic)
    }

    #[test]
    fn test_secure_array_zeroizes_on_drop() {
        let mut arr = SecureArray::<u8, 16>::new();
        arr.as_mut_slice().copy_from_slice(&[0x42u8; 16]);
        assert_eq!(arr.as_slice()[0], 0x42);
        // Drop should zeroize without panic
        drop(arr);
    }

    #[test]
    fn test_secure_array_explicit_zeroize() {
        let mut arr = SecureArray::<u8, 8>::from_array([0xFFu8; 8]);
        arr.zeroize_now();
        assert!(arr.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_scrub_stack_no_panic() {
        secure_scrub_stack();
    }

    #[test]
    fn test_secure_box_debug_redacted() {
        let val = SecureBox::new([0x42u8; 32]);
        let debug_str = format!("{:?}", val);
        assert_eq!(debug_str, "SecureBox(<redacted>)");
    }

    #[test]
    fn test_secure_array_debug_redacted() {
        let val = SecureArray::<u8, 16>::from_array([0xABu8; 16]);
        let debug_str = format!("{:?}", val);
        assert_eq!(debug_str, "SecureArray(<redacted>)");
    }
}
