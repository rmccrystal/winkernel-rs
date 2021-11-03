use crate::basedef::*;
use core::ptr;
use crate::ntstatus::NtStatus;
use ntapi::ntpebteb::PPEB;
use cstr_core::CStr;

extern "system" {
    pub fn PsLookupProcessByProcessId(process_id: HANDLE, process: *mut PEPROCESS) -> NtStatus;
    pub fn PsGetProcessPeb(process: PEPROCESS) -> PPEB;
    pub fn IoGetCurrentProcess() -> PEPROCESS;
    pub fn PsGetProcessImageFileName(process: PEPROCESS) -> *const u8;
}

pub struct Process(pub PEPROCESS);

impl Process {
    pub fn from_peprocess(proc: PEPROCESS) -> Self {
        Self(proc)
    }

    pub unsafe fn current() -> Self {
        Self::from_peprocess(IoGetCurrentProcess())
    }

    pub unsafe fn file_name(&self) -> &str {
        let buf = PsGetProcessImageFileName(self.0);
        CStr::from_ptr(buf as _).to_str().unwrap()
    }

    pub unsafe fn by_pid(pid: u64) -> Result<Self, NTSTATUS> {
        let mut proc: PEPROCESS = ptr::null_mut();
        PsLookupProcessByProcessId(pid as HANDLE, &mut proc)
            .to_result_with_value(Self(proc))
    }

    pub unsafe fn peb(&self) -> PPEB {
        PsGetProcessPeb(self.0)
    }
}