use crate::basedef::NTSTATUS;

#[repr(transparent)]
pub struct NtStatus(pub NTSTATUS);

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum NtStatusType {
    Success,
    Information,
    Warning,
    Error,
}

impl NtStatus {
    pub fn get_type(&self) -> NtStatusType {
        match self.0 {
            s if nt_information(s) => NtStatusType::Information,
            s if nt_success(s) => NtStatusType::Success,
            s if nt_warning(s) => NtStatusType::Warning,
            s if nt_error(s) => NtStatusType::Error,
            _ => unreachable!()
        }
    }

    pub fn is_success(&self) -> bool {
        self.get_type() == NtStatusType::Success
    }

    pub fn is_warning(&self) -> bool {
        self.get_type() == NtStatusType::Warning
    }

    pub fn is_error(&self) -> bool {
        self.get_type() == NtStatusType::Error
    }

    pub fn to_result(&self) -> Result<(), NTSTATUS> {
        match self.get_type() {
            NtStatusType::Error => Err(self.0),
            _ => Ok(())
        }
    }

    pub fn to_result_with_value<T>(&self, value: T) -> Result<T, NTSTATUS> {
        match self.get_type() {
            NtStatusType::Error => Err(self.0),
            _ => Ok(value)
        }
    }
}

impl From<NTSTATUS> for NtStatus {
    fn from(s: NTSTATUS) -> Self {
        Self(s)
    }
}

/// Evaluates to TRUE if the return value specified by Status is a success type (0 − 0x3FFFFFFF) or an informational type (0x40000000 − 0x7FFFFFFF).
pub fn nt_success(status: NTSTATUS) -> bool {
    (0..=0x7FFFFFFF).contains(&(status as u32))
}

/// Evaluates to TRUE if the return value specified by Status is an informational type (0x40000000 − 0x7FFFFFFF).
pub fn nt_information(status: NTSTATUS) -> bool {
    (0x40000000..=0x7FFFFFFF).contains(&(status as u32))
}

/// Evaluates to TRUE if the return value specified by Status is a warning type (0x80000000 − 0xBFFFFFFF).
pub fn nt_warning(status: NTSTATUS) -> bool {
    (0x80000000..=0xBFFFFFFF).contains(&(status as u32))
}

/// Evaluates to TRUE if the return value specified by Status is an error type (0xC0000000 - 0xFFFFFFFF).
pub fn nt_error(status: NTSTATUS) -> bool {
    (0xC0000000..=0xFFFFFFFF).contains(&(status as u32))
}