/// Returns a raw slice of the account's bytes.
#[macro_export]
macro_rules! impl_to_bytes {
    ($struct_name:ident) => {
        impl $struct_name {
            #[inline]
            pub fn to_bytes(&self) -> &[u8] {
                // SAFETY:
                // 1. `self` lives as long as the returned slice,
                // 2. pointer is aligned to `align_of::<Self>()`,
                // 3. length is exactly `size_of::<Self>()`.
                unsafe {
                    core::slice::from_raw_parts(
                        self as *const _ as *const u8,
                        core::mem::size_of::<Self>(),
                    )
                }
            }
        }
    };
}

/// Returns a mutable raw slice of the account's bytes.
#[macro_export]
macro_rules! impl_to_bytes_mut {
    ($struct_name:ident) => {
        impl $struct_name {
            #[inline]
            pub fn to_bytes_mut(&mut self) -> &mut [u8] {
                // SAFETY:
                // 1. `self` lives as long as the returned slice,
                // 2. pointer is aligned to `align_of::<Self>()`,
                // 3. length is exactly `size_of::<Self>()`.
                unsafe {
                    core::slice::from_raw_parts_mut(
                        self as *mut _ as *mut u8,
                        core::mem::size_of::<Self>(),
                    )
                }
            }
        }
    };
}

#[macro_export]
macro_rules! account {
    ($discriminator_name:ident, $struct_name:ident) => {
        impl $crate::Account for $struct_name {}

        impl $crate::Discriminator for $struct_name {
            #[inline(always)]
            fn discriminator() -> u8 {
                $discriminator_name::$struct_name as u8
            }
        }

        impl $crate::AccountValidation for $struct_name {
            #[track_caller]
            fn assert<F>(
                &self,
                condition: F,
            ) -> Result<&Self, pinocchio::program_error::ProgramError>
            where
                F: Fn(&Self) -> bool,
            {
                if !condition(self) {
                    return Err($crate::trace(
                        "Account data is invalid",
                        pinocchio::program_error::ProgramError::InvalidAccountData,
                    ));
                }
                Ok(self)
            }

            #[track_caller]
            fn assert_err<F, E>(
                &self,
                condition: F,
                err: E,
            ) -> Result<&Self, pinocchio::program_error::ProgramError>
            where
                F: Fn(&Self) -> bool,
                E: Into<pinocchio::program_error::ProgramError>,
            {
                if !condition(self) {
                    return Err(err.into());
                }
                Ok(self)
            }

            #[track_caller]
            fn assert_mut<F>(
                &mut self,
                condition: F,
            ) -> Result<&mut Self, pinocchio::program_error::ProgramError>
            where
                F: Fn(&Self) -> bool,
            {
                if !condition(self) {
                    return Err($crate::trace(
                        "Account data is invalid",
                        pinocchio::program_error::ProgramError::InvalidAccountData,
                    ));
                }
                Ok(self)
            }

            #[track_caller]
            fn assert_mut_err<F, E>(
                &mut self,
                condition: F,
                err: E,
            ) -> Result<&mut Self, pinocchio::program_error::ProgramError>
            where
                F: Fn(&Self) -> bool,
                E: Into<pinocchio::program_error::ProgramError>,
            {
                if !condition(self) {
                    return Err(err.into());
                }
                Ok(self)
            }
        }
    };
}

#[macro_export]
macro_rules! error {
    ($struct_name:ident) => {
        impl From<$struct_name> for pinocchio::program_error::ProgramError {
            fn from(e: $struct_name) -> Self {
                pinocchio_log::log!(
                    "Error Number: {}. Error Message: {}.",
                    e as u32,
                    e.message()
                );
                pinocchio::program_error::ProgramError::Custom(e as u32)
            }
        }
    };
}

/// Declare a log-gable event struct.
#[macro_export]
macro_rules! event {
    ($struct_name:ident) => {
        $crate::impl_to_bytes!($struct_name);

        impl $crate::Loggable for $struct_name {
            fn log(&self) {
                pinocchio::log::sol_log_data(&[&self.to_bytes()]);
            }
            fn log_return(&self) {
                pinocchio::program::set_return_data(&self.to_bytes());
            }
        }
    };
}

#[macro_export]
macro_rules! instruction {
    ($discriminator_name:ident, $struct_name:ident) => {
        impl $crate::Instruction for $struct_name {}

        impl $crate::Discriminator for $struct_name {
            #[inline(always)]
            fn discriminator() -> u8 {
                $discriminator_name::$struct_name as u8
            }
        }

        // Compared to a standard "to_bytes" impl add a header with discriminator
        impl $struct_name {
            pub fn to_bytes(&self) -> $crate::alloc::vec::Vec<u8> {
                unsafe {
                    [
                        [$discriminator_name::$struct_name as u8].to_vec(),
                        core::slice::from_raw_parts(
                            self as *const _ as *const u8,
                            core::mem::size_of::<Self>(),
                        )
                        .to_vec(),
                    ]
                    .concat()
                }
            }
        }
    };
}
