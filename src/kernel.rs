use winapi::ctypes::c_void;
use core::ptr::{null_mut, NonNull};
use crate::basedef::*;
use crate::ntstatus::NtStatus;
use ntapi::ntexapi::{SYSTEM_INFORMATION_CLASS, SystemModuleInformation, SystemProcessInformation, SYSTEM_THREAD_INFORMATION};
use crate::vsb::VariableSizedBox;
use ntapi::ntzwapi::ZwQuerySystemInformation;
use alloc::prelude::v1::*;
use ntapi::ntldr::RTL_PROCESS_MODULES;
use core::{slice, mem};
use ntapi::ntapi_base::KPRIORITY;
use winapi::shared::basetsd::{ULONG_PTR, SIZE_T, PSIZE_T};
use crate::string::UnicodeString;
use ntapi::ntrtl::RtlFindExportedRoutineByName;
use cstr_core::CString;
use crate::basedef::ntapi::ntobapi::POBJECT_NAME_INFORMATION;
use ntapi::ntobapi::OBJECT_NAME_INFORMATION;
use alloc::string::FromUtf16Error;

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
        return Err(ntstatus::STATUS_ACCESS_DENIED);
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

    if size == 0 {
        return Err(ntstatus::STATUS_UNSUCCESSFUL);
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
    pub section: HANDLE,
    pub mapped_base: usize,
    pub image_base: usize,
    pub image_size: ULONG,
    pub flags: ULONG,
    pub load_order_index: USHORT,
    pub init_order_index: USHORT,
    pub load_count: USHORT,
    pub offset_to_file_name: USHORT,
    pub full_path_name: [UCHAR; 256],
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
    pub next_entry_offset: ULONG,
    pub number_of_threads: ULONG,
    pub working_set_private_size: i64,
    pub hard_fault_count: ULONG,
    pub number_of_threads_high_watermark: ULONG,
    pub cycle_time: ULONGLONG,
    pub create_time: i64,
    pub user_time: i64,
    pub kernel_time: i64,
    pub image_name: UnicodeString,
    pub base_priority: KPRIORITY,
    pub unique_process_id: HANDLE,
    pub inherited_from_unique_process_id: HANDLE,
    pub handle_count: ULONG,
    pub session_id: ULONG,
    pub unique_process_key: ULONG_PTR,
    pub peak_virtual_size: SIZE_T,
    pub virtual_size: SIZE_T,
    pub page_fault_count: ULONG,
    pub peak_working_set_size: SIZE_T,
    pub working_set_size: SIZE_T,
    pub quota_peak_paged_pool_usage: SIZE_T,
    pub quota_paged_pool_usage: SIZE_T,
    pub quota_peak_non_paged_pool_usage: SIZE_T,
    pub quota_non_paged_pool_usage: SIZE_T,
    pub pagefile_usage: SIZE_T,
    pub peak_pagefile_usage: SIZE_T,
    pub private_page_count: SIZE_T,
    pub read_operation_count: i64,
    pub write_operation_count: i64,
    pub other_operation_count: i64,
    pub read_transfer_count: i64,
    pub write_transfer_count: i64,
    pub other_transfer_count: i64,
    pub threads: [SYSTEM_THREAD_INFORMATION; 1],
}

pub unsafe fn get_process_list() -> Result<Vec<SystemProcessInformation>, NTSTATUS> {
    let buf = query_system_information::<SystemProcessInformation>(SystemProcessInformation)?;

    let mut info = buf.as_ptr();
    let mut structs = Vec::new();

    loop {
        structs.push(*info);

        match (*info).next_entry_offset {
            0 => break,
            offset => info = (info as usize + offset as usize) as _
        }
    }

    Ok(structs)
}

#[repr(u32)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum RegNotifyClass {
    RegNtPreDeleteKey = 0,
    RegNtPreSetValueKey = 1,
    RegNtPreDeleteValueKey = 2,
    RegNtPreSetInformationKey = 3,
    RegNtPreRenameKey = 4,
    RegNtPreEnumerateKey = 5,
    RegNtPreEnumerateValueKey = 6,
    RegNtPreQueryKey = 7,
    RegNtPreQueryValueKey = 8,
    RegNtPreQueryMultipleValueKey = 9,
    RegNtPreCreateKey = 10,
    RegNtPostCreateKey = 11,
    RegNtPreOpenKey = 12,
    RegNtPostOpenKey = 13,
    RegNtPreKeyHandleClose = 14,
    RegNtPostDeleteKey = 15,
    RegNtPostSetValueKey = 16,
    RegNtPostDeleteValueKey = 17,
    RegNtPostSetInformationKey = 18,
    RegNtPostRenameKey = 19,
    RegNtPostEnumerateKey = 20,
    RegNtPostEnumerateValueKey = 21,
    RegNtPostQueryKey = 22,
    RegNtPostQueryValueKey = 23,
    RegNtPostQueryMultipleValueKey = 24,
    RegNtPostKeyHandleClose = 25,
    RegNtPreCreateKeyEx = 26,
    RegNtPostCreateKeyEx = 27,
    RegNtPreOpenKeyEx = 28,
    RegNtPostOpenKeyEx = 29,
    RegNtPreFlushKey = 30,
    RegNtPostFlushKey = 31,
    RegNtPreLoadKey = 32,
    RegNtPostLoadKey = 33,
    RegNtPreUnLoadKey = 34,
    RegNtPostUnLoadKey = 35,
    RegNtPreQueryKeySecurity = 36,
    RegNtPostQueryKeySecurity = 37,
    RegNtPreSetKeySecurity = 38,
    RegNtPostSetKeySecurity = 39,
    RegNtCallbackObjectContextCleanup = 40,
    MaxRegNtNotifyClass = 41,
}

extern "system" {
    pub fn CmRegisterCallback(
        func: *mut c_void,
        context: *mut c_void,
        cookie: *mut u64,
    );

    pub fn CmUnRegisterCallback(cookie: u64);
}

pub type RegistryCallbackFunc<T> = extern "C" fn(callback_context: &mut T, class: RegNotifyClass, operation: *mut c_void) -> NTSTATUS;

pub unsafe fn create_registry_callback<T>(func: RegistryCallbackFunc<T>, context: &'static mut T) -> RegistryCallback {
    let mut cookie = 0;
    CmRegisterCallback(func as _, context as *mut T as _, &mut cookie);
    RegistryCallback(cookie)
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct RegistryCallback(pub u64);

impl RegistryCallback {
    pub unsafe fn unregister(&self) {
        CmUnRegisterCallback(self.0);
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct RegSetValueKeyInformation {
    pub object: PVOID,
    pub value_name: &'static UnicodeString,
    pub title_index: ULONG,
    pub reg_type: ULONG,
    pub data: PVOID,
    pub data_size: ULONG,
    pub call_context: PVOID,
    pub object_context: PVOID,
    pub reserved: PVOID,
}

impl RegSetValueKeyInformation {
    pub fn data(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.data as *const u8, self.data_size as _) }
    }
}

extern "system" {
    fn ObQueryNameString(
        object: PVOID,
        object_name_info: POBJECT_NAME_INFORMATION,
        length: ULONG,
        return_length: PULONG,
    ) -> NtStatus;
}

pub unsafe fn get_object_name(object: PVOID) -> Result<String, NTSTATUS> {
    if object.is_null() {
        return Err(ntstatus::STATUS_NOT_FOUND);
    }

    let mut len = 0;
    let result = ObQueryNameString(object, null_mut(), 0, &mut len);
    if result.0 != ntstatus::STATUS_INFO_LENGTH_MISMATCH {
        return Err(ntstatus::STATUS_NOT_FOUND);
    }

    let mut name_info = VariableSizedBox::new(len as usize);
    ObQueryNameString(object, name_info.as_mut_ptr(), len, &mut len).to_result()?;

    let name: UnicodeString = name_info.as_ref().Name.into();
    match name.try_to_string() {
        Ok(s) => Ok(s),
        Err(_) => Err(ntstatus::STATUS_UNSUCCESSFUL)
    }
}

extern "system" {
    fn MmCopyMemory(
        target_address: PVOID,
        source_address: u64,
        number_of_bytes: SIZE_T,
        flags: ULONG,
        number_of_bytes_transferred: PSIZE_T,
    ) -> NtStatus;
}

const MM_COPY_MEMORY_PHYSICAL: ULONG = 0x1;
const MM_COPY_MEMORY_VIRTUAL: ULONG = 0x2;

pub unsafe fn read_physical(address: u64, buf: &mut [u8]) -> Result<(), NTSTATUS> {
    let mut bytes: usize = 0;
    MmCopyMemory(buf.as_mut_ptr() as _, address, buf.len(), MM_COPY_MEMORY_PHYSICAL, &mut bytes).to_result()?;
    if bytes < buf.len() {
        return Err(ntstatus::STATUS_PARTIAL_COPY);
    }

    Ok(())
}

extern "C" {
    pub fn KeQueryPerformanceCounter(performance_frequency: *mut u64) -> u64;
}

pub unsafe fn query_performance_counter() -> u64 {
    KeQueryPerformanceCounter(null_mut())
}