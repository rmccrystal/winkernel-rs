use winapi::ctypes::c_void;
use core::ptr::{null_mut, NonNull};
use crate::basedef::*;
use crate::ntstatus::NtStatus;
use ntapi::ntexapi::{SYSTEM_INFORMATION_CLASS, SystemModuleInformation, SystemProcessInformation, SYSTEM_THREAD_INFORMATION};
use crate::vsb::VariableSizedBox;
use ntapi::ntzwapi::ZwQuerySystemInformation;
use alloc::prelude::v1::*;
use ntapi::ntldr::RTL_PROCESS_MODULES;
use core::slice;
use ntapi::ntapi_base::KPRIORITY;
use winapi::shared::basetsd::{ULONG_PTR, SIZE_T};
use crate::string::UnicodeString;
use ntapi::ntrtl::RtlFindExportedRoutineByName;
use cstr_core::CString;

#[allow(non_camel_case_types)]
#[repr(i32)]
pub enum LOCK_OPERATION {
    IoReadAccess = 0,
    IoWriteAccess = 1,
    IoModifyAccess = 2,
}

#[allow(non_camel_case_types)]
#[repr(i32)]
pub enum MEMORY_CACHING_TYPE {
    MmNonCached = 0,
    MmCached = 1,
    MmWriteCombined = 2,
    MmHardwareCoherentCached = 3,
    MmNonCachedUnordered = 4,
    MmUSWCCached = 5,
    MmMaximumCacheType = 6,
    MmNotMapped = -1,
}

extern "system" {
    fn IoAllocateMdl(
        virtual_address: *mut c_void,
        length: u32,
        secondary_buffer: u8,
        charge_quota: u8,
        irp: *mut c_void,
    ) -> PMDL;

    pub fn MmProbeAndLockPages(
        memory_descriptor_list: PMDL,
        access_mode: KPROCESSOR_MODE,
        operation: LOCK_OPERATION,
    );

    pub fn MmMapLockedPagesSpecifyCache(
        memory_descriptor_list: PMDL,
        access_mode: KPROCESSOR_MODE,
        cache_type: MEMORY_CACHING_TYPE,
        requested_address: PVOID,
        bug_check_on_failure: ULONG,
        priority: ULONG,
    ) -> PVOID;

    pub fn MmProtectMdlSystemAddress(memory_descriptor_list: PMDL, new_protect: ULONG) -> NtStatus;

    pub fn MmUnmapLockedPages(base_address: PVOID, memory_descriptor_list: PMDL);
    pub fn MmUnlockPages(memory_descriptor_list: PMDL);
    pub fn IoFreeMdl(mdl: PMDL);
}

pub unsafe fn safe_copy(src: *const u8, dst: *mut u8, len: usize) -> Result<(), NTSTATUS> {
    let mdl = IoAllocateMdl(dst as _, len as _, 0, 0, null_mut());
    if mdl.is_null() {
        return Err(STATUS_ACCESS_DENIED)
    }

    MmProbeAndLockPages(mdl, KPROCESSOR_MODE::KernelMode, LOCK_OPERATION::IoReadAccess);
    let map = MmMapLockedPagesSpecifyCache(
        mdl,
        KPROCESSOR_MODE::KernelMode,
        MEMORY_CACHING_TYPE::MmNonCached,
        null_mut(),
        FALSE as u32,
        16, // NormalPagePriority
    );

    MmProtectMdlSystemAddress(mdl, 0x04 /* PAGE_READWRITE */).to_result()?;

    core::ptr::copy_nonoverlapping(src, map as _, len);

    MmUnmapLockedPages(map, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);

    Ok(())
}

pub unsafe fn query_system_information<T>(class: SYSTEM_INFORMATION_CLASS) -> Result<VariableSizedBox<T>, NTSTATUS> {
    let mut size = 0;
    let status = ZwQuerySystemInformation(
        class,
        null_mut(),
        size,
        &mut size,
    );
    NtStatus(status).to_result()?;

    if size == 0 {
        return Err(STATUS_UNSUCCESSFUL);
    }

    let mut buf: VariableSizedBox<T> = VariableSizedBox::new(size as _);

    let status = ZwQuerySystemInformation(
        class,
        buf.as_mut_ptr() as _,
        size,
        &mut size,
    );
    NtStatus(status).to_result()?;

    Ok(buf)
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ProcessModuleInformation {
    section: HANDLE,
    mapped_base: usize,
    image_base: usize,
    image_size: ULONG,
    flags: ULONG,
    load_order_index: USHORT,
    init_order_index: USHORT,
    load_count: USHORT,
    offset_to_file_name: USHORT,
    full_path_name: [UCHAR; 256],
}

impl ProcessModuleInformation {
    pub unsafe fn full_path(&self) -> &str {
        crate::util::str_from_slice_unchecked(self.full_path_name.as_slice())
    }

    pub unsafe fn get_export(&self, func_name: &str) -> Option<NonNull<c_void>> {
        get_kernel_export(self.image_base, func_name)
    }
}

pub unsafe fn get_kernel_modules() -> Result<Vec<ProcessModuleInformation>, NTSTATUS> {
    let buf = query_system_information::<RTL_PROCESS_MODULES>(SystemModuleInformation)?;
    let modules = slice::from_raw_parts(buf.as_ref().Modules.as_ptr() as *const ProcessModuleInformation, buf.as_ref().NumberOfModules as usize);
    Ok(modules.to_vec())
}

pub unsafe fn get_kernel_export(module_base: usize, func_name: &str) -> Option<NonNull<c_void>> {
    let func_name = CString::new(func_name).unwrap();
    NonNull::new(RtlFindExportedRoutineByName(module_base as _, func_name.as_ptr() as _))
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SystemProcessInformation {
    next_entry_offset: ULONG,
    number_of_threads: ULONG,
    working_set_private_size: i64,
    hard_fault_count: ULONG,
    number_of_threads_high_watermark: ULONG,
    cycle_time: ULONGLONG,
    create_time: i64,
    user_time: i64,
    kernel_time: i64,
    image_name: UnicodeString,
    base_priority: KPRIORITY,
    unique_process_id: HANDLE,
    inherited_from_unique_process_id: HANDLE,
    handle_count: ULONG,
    session_id: ULONG,
    unique_process_key: ULONG_PTR,
    peak_virtual_size: SIZE_T,
    virtual_size: SIZE_T,
    page_fault_count: ULONG,
    peak_working_set_size: SIZE_T,
    working_set_size: SIZE_T,
    quota_peak_paged_pool_usage: SIZE_T,
    quota_paged_pool_usage: SIZE_T,
    quota_peak_non_paged_pool_usage: SIZE_T,
    quota_non_paged_pool_usage: SIZE_T,
    pagefile_usage: SIZE_T,
    peak_pagefile_usage: SIZE_T,
    private_page_count: SIZE_T,
    read_operation_count: i64,
    write_operation_count: i64,
    other_operation_count: i64,
    read_transfer_count: i64,
    write_transfer_count: i64,
    other_transfer_count: i64,
    threads: [SYSTEM_THREAD_INFORMATION; 1],
}

pub unsafe fn get_process_list() -> Result<Vec<SystemProcessInformation>, NTSTATUS> {
    let buf = query_system_information::<SystemProcessInformation>(SystemProcessInformation)?;

    let mut info = buf.as_ptr();
    let mut structs = Vec::new();

    loop {
        structs.push(*info);

        match (*info).next_entry_offset {
            0 => break,
            n => info = (info as u32 + n) as _
        }
    }

    Ok(structs)
}
