use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;

#[repr(C)]
pub enum PoolType {
    NonPagedPool,
    NonPagedPoolExecute,
}

#[link(name = "ntoskrnl")]
extern "system" {
    pub fn ExAllocatePoolWithTag(pool_type: PoolType, number_of_bytes: usize, tag: u32) -> *mut c_void;
    pub fn ExFreePoolWithTag(pool: *mut c_void, tag: u32);
}

static ALLOC_TAG: u32 = u32::from_le_bytes(*b"krnl");

/// The global kernel allocator structure.
pub struct KernelAlloc;

unsafe impl GlobalAlloc for KernelAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pool = ExAllocatePoolWithTag(PoolType::NonPagedPool, layout.size() as _, ALLOC_TAG);


        if pool.is_null() {
            panic!("Failed to allocate pool");
        }

        pool as _
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        ExFreePoolWithTag(ptr as _, ALLOC_TAG);
    }
}

#[alloc_error_handler]
#[cfg(not(test))]
fn alloc_error(layout: Layout) -> ! {
    panic!("{:?} alloc memory error", layout);
}
