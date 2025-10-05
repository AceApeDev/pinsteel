use pinocchio::program_error::ProgramError;

// Tag traits to distinguish between data types
pub trait Account {}
pub trait Instruction {}

use crate::trace;

pub trait Discriminator {
    fn discriminator() -> u8;
}

pub trait AccountDeserialize {
    fn try_from_bytes(data: &[u8]) -> Result<&Self, ProgramError>;
    fn try_from_bytes_mut(data: &mut [u8]) -> Result<&mut Self, ProgramError>;
}

impl<T> AccountDeserialize for T
where
    T: Discriminator + Account,
{
    #[inline]
    fn try_from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        /* 1. Validate bytes length */
        if data.len() != core::mem::size_of::<Self>() {
            return Err(trace(
                "Account has wrong length",
                ProgramError::InvalidAccountData,
            ));
        }

        /* 2. Check discriminator */
        if Self::discriminator().ne(&data[0]) {
            return Err(trace(
                "Account has wrong discriminator",
                ProgramError::InvalidAccountData,
            ));
        }

        /* 3. Check alignment */
        if (data.as_ptr() as usize) % core::mem::align_of::<Self>() != 0 {
            return Err(trace(
                "Account has wrong alignment",
                ProgramError::InvalidAccountData,
            ));
        }

        /* 4. Zero-copy cast */
        // SAFETY: length, discriminator and alignment are checked above
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }

    #[inline]
    fn try_from_bytes_mut(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        /* 1. Validate bytes length */
        if data.len() != core::mem::size_of::<Self>() {
            return Err(trace(
                "Account has wrong length",
                ProgramError::InvalidAccountData,
            ));
        }

        /* 2. Check discriminator */
        if Self::discriminator().ne(&data[0]) {
            return Err(trace(
                "Account has wrong discriminator",
                ProgramError::InvalidAccountData,
            ));
        }

        /* 3. Check alignment */
        if (data.as_ptr() as usize) % core::mem::align_of::<Self>() != 0 {
            return Err(trace(
                "Account has wrong alignment",
                ProgramError::InvalidAccountData,
            ));
        }

        /* 4. Zero-copy cast */
        // SAFETY: length, discriminator and alignment are checked above
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }
}

pub trait InstructionDeserialize {
    fn try_from_bytes(data: &[u8]) -> Result<&Self, ProgramError>;
}

impl<T> InstructionDeserialize for T
where
    T: Instruction,
{
    #[inline]
    fn try_from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        /* 1. Validate bytes length */
        if data.len() != core::mem::size_of::<Self>() {
            return Err(ProgramError::InvalidInstructionData);
        }

        /* 2. Check alignment */
        if (data.as_ptr() as usize) % core::mem::align_of::<Self>() != 0 {
            return Err(ProgramError::InvalidInstructionData);
        }

        /* 3. Zero-copy cast */
        // SAFETY: length, discriminator and alignment are checked above
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }
}

// Account data is sometimes stored via a header and body type,
/// where the former resolves the type of the latter (e.g. merkle trees with a generic size const).
/// This trait parses a header type from the first N bytes of some data, and returns the remaining
/// bytes, which are then available for further processing.
pub trait AccountHeaderDeserialize {
    fn try_header_from_bytes(data: &[u8]) -> Result<(&Self, &[u8]), ProgramError>;
    fn try_header_from_bytes_mut(data: &mut [u8]) -> Result<(&mut Self, &mut [u8]), ProgramError>;
}

impl<T> AccountHeaderDeserialize for T
where
    T: Discriminator + Account,
{
    #[inline]
    fn try_header_from_bytes(data: &[u8]) -> Result<(&Self, &[u8]), ProgramError> {
        /* 1. Validate bytes length */
        if data.len() < core::mem::size_of::<Self>() {
            return Err(ProgramError::InvalidAccountData);
        }

        /* 2. Check discriminator */
        if Self::discriminator().ne(&data[0]) {
            return Err(ProgramError::InvalidAccountData);
        }

        /* 3. Split into header and body */
        let (header, body) = data.split_at(core::mem::size_of::<Self>());

        /* 4. Check header alignment */
        if (header.as_ptr() as usize) % core::mem::align_of::<Self>() != 0 {
            return Err(ProgramError::InvalidAccountData);
        }

        /* 5. Zero-copy cast */
        // SAFETY: length, discriminator and alignment are checked above
        Ok((unsafe { &*(header.as_ptr() as *const Self) }, body))
    }

    #[inline]
    fn try_header_from_bytes_mut(data: &mut [u8]) -> Result<(&mut Self, &mut [u8]), ProgramError> {
        /* 1. Validate bytes length */
        if data.len() < core::mem::size_of::<Self>() {
            return Err(ProgramError::InvalidAccountData);
        }

        /* 2. Check discriminator */
        if Self::discriminator().ne(&data[0]) {
            return Err(ProgramError::InvalidAccountData);
        }

        /* 3. Split into header and body */
        let (header, body) = data.split_at_mut(core::mem::size_of::<Self>());

        /* 4. Check header alignment */
        if (header.as_ptr() as usize) % core::mem::align_of::<Self>() != 0 {
            return Err(ProgramError::InvalidAccountData);
        }

        /* 4. Zero-copy cast */
        // SAFETY: length, discriminator and alignment are checked above
        Ok((unsafe { &mut *(header.as_mut_ptr() as *mut Self) }, body))
    }
}

pub trait InstructionHeaderDeserialize {
    fn try_header_from_bytes(data: &[u8]) -> Result<(&Self, &[u8]), ProgramError>;
}

impl<T> InstructionHeaderDeserialize for T
where
    T: Instruction,
{
    #[inline]
    fn try_header_from_bytes(data: &[u8]) -> Result<(&Self, &[u8]), ProgramError> {
        /* 1. Validate bytes length */
        if data.len() < core::mem::size_of::<Self>() {
            return Err(ProgramError::InvalidInstructionData);
        }

        /* 2. Split into header and body */
        let (header, body) = data.split_at(core::mem::size_of::<Self>());

        /* 3. Check header alignment */
        if (header.as_ptr() as usize) % core::mem::align_of::<Self>() != 0 {
            return Err(ProgramError::InvalidInstructionData);
        }

        /* 4. Zero-copy cast */
        // SAFETY: length, discriminator and alignment are checked above
        Ok((unsafe { &*(header.as_ptr() as *const Self) }, body))
    }
}
