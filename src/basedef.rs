//! Kernel-Mode Types.
#![allow(non_camel_case_types)]

pub use winapi::shared::ntdef::*;
use core::ffi::c_void;
pub use winapi::shared::ntstatus::*;

pub type PEPROCESS = *mut c_void;
pub type PMDL = *mut c_void;

/// Processor modes.
#[repr(u8)]
#[derive(Copy, Clone)]
pub enum KPROCESSOR_MODE
{
    KernelMode,
    UserMode,
}

