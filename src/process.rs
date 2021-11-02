use crate::basedef::*;
use core::ptr;
use crate::ntstatus::NtStatus;
use ntapi::ntpebteb::PPEB;

extern "system" {
    pub fn PsLookupProcessByProcessId(process_id: HANDLE, process: *mut PEPROCESS) -> NtStatus;
    pub fn PsGetProcessPeb(Process: PEPROCESS) -> PPEB;
}

pub struct Process(pub PEPROCESS);

impl Process {
    pub fn from_peprocess(proc: PEPROCESS) -> Self {
        Self(proc)
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