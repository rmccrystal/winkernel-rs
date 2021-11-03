use log::{Level, LevelFilter, Metadata, Record, SetLoggerError};
use alloc::string::String;

extern "cdecl" {
    pub fn DbgPrintEx(component_id: u32, level: u32, fmt: *const u8, ...) -> i32;
}

/// Prints a string using DbgPrintEx. Automatically adds a null terminator
pub fn __kernel_print(mut text: String) {
    text.push('\n');
    text.push('\0');
    unsafe { DbgPrintEx(0, 0, text.as_ptr()) };
}

#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => ({
        ::winkernel::log::__kernel_print(alloc::format!($($arg)*));
    })
}

#[macro_export]
macro_rules! dbg {
    () => {
        ::winkernel::println!("[{}:{}]", $crate::file!(), $crate::line!());
    };
    ($val:expr $(,)?) => {
        // Use of `match` here is intentional because it affects the lifetimes
        // of temporaries - https://stackoverflow.com/a/48732525/1063961
        match $val {
            tmp => {
                ::winkernel::println!("[{}:{}] {} = {:#?}",
                    core::file!(), core::line!(), core::stringify!($val), &tmp);
                tmp
            }
        }
    };
    ($($val:expr),+ $(,)?) => {
        ($($crate::dbg!($val)),+,)
    };
}

pub struct KernelLogger {
    pub prefix: &'static str,
}

static mut LOGGER: KernelLogger = KernelLogger { prefix: "" };

impl KernelLogger {
    pub fn init(level: LevelFilter, prefix: &'static str) -> Result<(), SetLoggerError> {
        unsafe {
            LOGGER.prefix = prefix;
            log::set_logger(&LOGGER)
                .map(|()| log::set_max_level(level))
        }
    }
}

impl log::Log for KernelLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let prefix = match record.level() {
            Level::Error => "[ERROR]",
            Level::Warn => "[!]",
            Level::Info => "[+]",
            Level::Debug => "[*]",
            Level::Trace => "[?]",
        };

        __kernel_print(alloc::format!("[{}] {} {}", self.prefix, prefix, record.args()));
    }

    fn flush(&self) {}
}
