use core::panic::Location;
use pinocchio::program_error::ProgramError;
use pinocchio_log::log;

/// Logs the call trace and returns the error.
#[track_caller]
pub fn trace(msg: &str, error: ProgramError) -> ProgramError {
    let here = Location::caller();
    log!("{}:{} {}", here.file(), here.line(), msg);
    error
}

/// Supports logging.
pub trait Loggable {
    fn log(&self);
    fn log_return(&self);
}
