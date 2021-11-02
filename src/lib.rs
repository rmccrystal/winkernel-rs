#![no_std]
#![feature(alloc_error_handler)]
#![feature(alloc_prelude)]
#![feature(core_intrinsics)]
#![allow(clippy::missing_safety_doc)]

extern crate alloc;

pub mod allocator;
pub mod log;
pub mod string;
pub mod kernel;
pub mod basedef;
pub mod ntstatus;
pub mod process;
pub mod vsb;
pub mod util;