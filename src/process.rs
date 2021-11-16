use core::ffi::c_void;
use crate::basedef::*;
use core::{mem, ptr};
use crate::ntstatus::NtStatus;
use ntapi::ntpebteb::PPEB;
use cstr_core::CStr;

extern "system" {
    pub fn PsLookupProcessByProcessId(process_id: HANDLE, process: *mut PeProcess) -> NtStatus;
    pub fn PsGetProcessPeb(process: PeProcess) -> PPEB;
    pub fn IoGetCurrentProcess() -> PeProcess;
    pub fn PsGetProcessImageFileName(process: PeProcess) -> *const u8;
    pub fn MmCopyVirtualMemory(from_process: PeProcess, from_address: *mut c_void, to_process: PeProcess, to_address: *mut c_void, size: usize, previous_mode: KProcessorMode, bytes_copied: &mut usize) -> NtStatus;
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct PeProcess(PEPROCESS);

impl PeProcess {
    pub fn from_peprocess(proc: PEPROCESS) -> Self {
        Self(proc)
    }

    pub unsafe fn current() -> Self {
        IoGetCurrentProcess()
    }

    pub unsafe fn file_name(&self) -> &str {
        let buf = PsGetProcessImageFileName(*self);
        CStr::from_ptr(buf as _).to_str().unwrap()
    }

    pub unsafe fn by_pid(pid: u64) -> Option<Self> {
        let mut proc: PeProcess = mem::zeroed();
        PsLookupProcessByProcessId(pid as HANDLE, &mut proc)
            .to_result_with_value(proc)
            .ok()
    }

    pub unsafe fn peb(&self) -> PPEB {
        PsGetProcessPeb(*self)
    }

    pub unsafe fn read_memory(&self, address: u64, buf: &mut [u8]) -> Result<(), NTSTATUS> {
        let mut bytes_copied = 0;
        MmCopyVirtualMemory(*self, address as _, Self::current(), buf.as_mut_ptr() as _, buf.len(), KProcessorMode::KernelMode, &mut bytes_copied);
        if bytes_copied < buf.len() {
            return Err(ntstatus::STATUS_UNSUCCESSFUL);
        }

        Ok(())
    }

    pub unsafe fn write_memory(&self, address: u64, buf: &[u8]) -> Result<(), NTSTATUS> {
        let mut bytes_copied = 0;
        MmCopyVirtualMemory(Self::current(), buf.as_ptr() as _, *self, address as _, buf.len(), KProcessorMode::KernelMode, &mut bytes_copied);
        if bytes_copied < buf.len() {
            return Err(ntstatus::STATUS_UNSUCCESSFUL);
        }

        Ok(())
    }
}