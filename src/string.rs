use alloc::prelude::v1::*;
use alloc::string::FromUtf16Error;

/// A counted Unicode string.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UnicodeString
{
    /// The length in **bytes** of the string stored in `Buffer`.
    pub length: u16,
    /// The length in **bytes** of `Buffer`.
    pub maximum_length: u16,
    /// Pointer to a buffer used to contain a string of wide characters.
    pub buffer: *const u16,
}

impl UnicodeString {
    pub unsafe fn try_to_string(&self) -> Result<String, FromUtf16Error> {
        String::from_utf16(self.as_slice())
    }

    pub unsafe fn as_slice(&self) -> &[u16] {
        core::slice::from_raw_parts(self.buffer, self.length as _)
    }

    pub fn from_slice(slice: &[u16]) -> Self {
        Self {
            length: slice.len() as _,
            maximum_length: slice.len() as _,
            buffer: slice.as_ptr()
        }
    }
}