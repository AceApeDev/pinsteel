use pinocchio::{
    account_info::{AccountInfo, Ref, RefMut},
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey, MAX_SEEDS, PDA_MARKER},
    ProgramResult,
};

#[cfg(target_os = "solana")]
use pinocchio::syscalls::sol_sha256;

use crate::{trace, AccountDeserialize, Discriminator, SYSVAR_PROGRAM_ID};

/// Build dynamic validation rules for AccountInfo
#[derive(Default)]
pub struct Validation<'a> {
    is_signer: bool,
    is_writable: bool,
    is_executable: bool,
    is_empty: bool,
    is_type: Option<(u8, &'a Pubkey)>,
    is_program: Option<&'a Pubkey>,
    is_sysvar: Option<&'a Pubkey>,
    has_address: Option<&'a Pubkey>,
    has_owner: Option<&'a Pubkey>,
    has_seeds: Option<(&'a [&'a [u8]], &'a Pubkey)>,
    has_seeds_with_bump: Option<(&'a [&'a [u8]], &'a Pubkey, u8)>,
    has_seeds_with_saved_bump: Option<(&'a [&'a [u8]], &'a Pubkey)>,
}

impl<'a> Validation<'a> {
    pub fn default() -> Self {
        Self {
            is_signer: false,
            is_writable: false,
            is_executable: false,
            is_empty: false,
            is_type: None,
            is_program: None,
            is_sysvar: None,
            has_address: None,
            has_owner: None,
            has_seeds: None,
            has_seeds_with_bump: None,
            has_seeds_with_saved_bump: None,
        }
    }

    pub const fn is_signer(mut self, must: bool) -> Self {
        self.is_signer = must;
        self
    }
    pub const fn is_writable(mut self, must: bool) -> Self {
        self.is_writable = must;
        self
    }
    pub const fn is_executable(mut self, must: bool) -> Self {
        self.is_executable = must;
        self
    }
    pub const fn is_empty(mut self, must: bool) -> Self {
        self.is_empty = must;
        self
    }
    pub const fn is_type(mut self, program_id: &'a Pubkey, discriminator: u8) -> Self {
        self.is_type = Some((discriminator, program_id));
        self
    }
    pub const fn is_program(mut self, program_id: &'a Pubkey) -> Self {
        self.is_program = Some(program_id);
        self
    }
    pub const fn is_sysvar(mut self, sysvar_id: &'a Pubkey) -> Self {
        self.is_sysvar = Some(sysvar_id);
        self
    }
    pub const fn has_address(mut self, address: &'a Pubkey) -> Self {
        self.has_address = Some(address);
        self
    }
    pub const fn has_owner(mut self, program_id: &'a Pubkey) -> Self {
        self.has_owner = Some(program_id);
        self
    }
    pub const fn has_seeds(mut self, seeds: &'a [&'a [u8]], program_id: &'a Pubkey) -> Self {
        self.has_seeds = Some((seeds, program_id));
        self
    }
    pub const fn has_seeds_with_bump(
        mut self,
        seeds: &'a [&'a [u8]],
        program_id: &'a Pubkey,
        bump: u8,
    ) -> Self {
        self.has_seeds_with_bump = Some((seeds, program_id, bump));
        self
    }
    pub const fn has_seeds_with_saved_bump(
        mut self,
        seeds: &'a [&'a [u8]],
        program_id: &'a Pubkey,
    ) -> Self {
        self.has_seeds_with_saved_bump = Some((seeds, program_id));
        self
    }

    #[must_use]
    pub fn run(self, ai: &AccountInfo) -> ProgramResult {
        // --------------- is_signer -------------------------------
        if self.is_signer && !ai.is_signer() {
            // return Err(trace("Account is not a signer", ProgramError::MissingRequiredSignature));
            return Err(ProgramError::MissingRequiredSignature);
        }

        // --------------- is_writable -------------------------------
        if self.is_writable && !ai.is_writable() {
            return Err(ProgramError::InvalidAccountData);
        }

        // --------------- is_executable -------------------------------
        if self.is_executable && !ai.executable() {
            return Err(ProgramError::InvalidAccountData);
        }

        // --------------- is_empty -------------------------------
        if self.is_empty && !ai.data_is_empty() {
            return Err(ProgramError::AccountAlreadyInitialized);
        }

        // --------------- is_type -------------------------------
        if let Some((discriminator, program_id)) = self.is_type {
            if !ai.is_owned_by(program_id) {
                return Err(ProgramError::InvalidAccountOwner);
            }

            // We only check discriminator, because we own account.
            if ai.try_borrow_data()?[0].ne(&discriminator) {
                return Err(ProgramError::InvalidAccountData);
            }
        }

        // // --------------- is_program -------------------------------
        if let Some(program_id) = self.is_program {
            if ai.key().ne(program_id) {
                return Err(ProgramError::InvalidAccountOwner);
            }
            if !ai.executable() {
                return Err(ProgramError::InvalidAccountData);
            }
        }

        // --------------- is_sysvar -------------------------------
        if let Some(sysvar_id) = self.is_sysvar {
            if !ai.is_owned_by(&SYSVAR_PROGRAM_ID) {
                return Err(ProgramError::InvalidAccountOwner);
            }
            if ai.key().ne(sysvar_id) {
                return Err(ProgramError::InvalidAccountData);
            }
        }

        // --------------- has_address -------------------------------
        if let Some(address) = self.has_address {
            if ai.key().ne(address) {
                return Err(ProgramError::InvalidAccountData);
            }
        }

        // // --------------- has_owner -------------------------------
        if let Some(owner) = self.has_owner {
            if !ai.is_owned_by(owner) {
                return Err(ProgramError::InvalidAccountOwner);
            }
        }

        // --------------- has_seeds -------------------------------
        // NOTE: Calling `find_program_address` is expensive.
        // Consider using `has_seeds_with_bump` instead for program owned accounts.
        if let Some((seeds, pid)) = self.has_seeds {
            let (pda, _bump) = find_program_address(seeds, pid);
            if ai.key().ne(&pda) {
                return Err(ProgramError::InvalidSeeds);
            }
        }

        // --------------- has_seeds_with_bump -------------------------------
        if let Some((seeds, pid, bump)) = self.has_seeds_with_bump {
            // Account must be initialized
            if ai.data_is_empty() || ai.data_len() < 2 {
                return Err(ProgramError::InvalidAccountData);
            }

            let bump_seed = [bump];
            let derived_pubkey = derive_pda(seeds, pid, bump_seed)?;

            // Check if the account key matches the derived PDA
            if ai.key().ne(&derived_pubkey) {
                return Err(ProgramError::InvalidSeeds);
            }
        }

        // --------------- has_seeds_with_saved_bump -------------------------------
        if let Some((seeds, pid)) = self.has_seeds_with_saved_bump {
            // Account must be owned by the program
            if !ai.is_owned_by(pid) {
                return Err(ProgramError::InvalidAccountOwner);
            }
            // Account must be initialized
            if ai.data_is_empty() || ai.data_len() < 2 {
                return Err(ProgramError::InvalidAccountData);
            }

            // SAFETY: bump should always be the second byte of account data
            let bump_seed = [ai.try_borrow_data()?[1]];
            let derived_pubkey = derive_pda(seeds, pid, bump_seed)?;

            // Check if the account key matches the derived PDA
            if ai.key().ne(&derived_pubkey) {
                return Err(ProgramError::InvalidSeeds);
            }
        }

        Ok(())
    }
}

fn derive_pda(
    seeds: &[&[u8]],
    program_id: &Pubkey,
    bump_seed: [u8; 1],
) -> Result<Pubkey, ProgramError> {
    // Create a proper slice array for sol_sha256
    let mut data: [&[u8]; MAX_SEEDS] = [&[]; MAX_SEEDS];
    let seeds_len = seeds.len();

    if seeds_len + 3 > MAX_SEEDS {
        return Err(ProgramError::InvalidSeeds);
    }

    // Add all provided seeds
    for (i, seed) in seeds.iter().enumerate() {
        data[i] = seed;
    }

    // Add bump, program_id, and PDA marker
    data[seeds_len] = &bump_seed;
    data[seeds_len + 1] = program_id.as_ref();
    data[seeds_len + 2] = PDA_MARKER.as_ref();

    let total_seeds = seeds_len + 3;
    let data_slice = &data[..total_seeds];

    let pda = {
        #[cfg(target_os = "solana")]
        {
            let mut result = [0u8; 32];
            unsafe {
                sol_sha256(
                    data_slice.as_ptr() as *const u8,
                    total_seeds as u64,
                    result.as_mut_ptr(),
                );
            }
            result
        }

        #[cfg(not(target_os = "solana"))]
        {
            unreachable!("deriving a pda is only available on target `solana`");
            #[allow(unreachable_code)]
            [0u8; 32] // Never executed, just for type satisfaction
        }
    };

    Ok(Pubkey::from(pda))
}
/// Performs:
/// 1. Program owner check
/// 2. Discriminator byte check
/// 3. Checked bytemuck conversion of account data to &T or &mut T.
pub trait AsAccount {
    fn as_account<T>(&self, program_id: &Pubkey) -> Result<Ref<T>, ProgramError>
    where
        T: AccountDeserialize + Discriminator;

    fn as_account_mut<T>(&self, program_id: &Pubkey) -> Result<RefMut<T>, ProgramError>
    where
        T: AccountDeserialize + Discriminator;
}

impl AsAccount for AccountInfo {
    fn as_account<T>(&self, program_id: &Pubkey) -> Result<Ref<T>, ProgramError>
    where
        T: AccountDeserialize + Discriminator,
    {
        // Validate account owner.
        if !self.is_owned_by(program_id) {
            return Err(trace(
                "Account has wrong owner",
                ProgramError::InvalidAccountOwner,
            ));
        }

        Ok(Ref::map(self.try_borrow_data()?, |data| {
            T::try_from_bytes(data).unwrap()
        }))
    }

    fn as_account_mut<T>(&self, program_id: &Pubkey) -> Result<RefMut<T>, ProgramError>
    where
        T: AccountDeserialize + Discriminator,
    {
        // Validate account owner.
        if !self.is_owned_by(program_id) {
            return Err(trace(
                "Account has wrong owner",
                ProgramError::InvalidAccountOwner,
            ));
        }
        Ok(RefMut::map(self.try_borrow_mut_data()?, |data| {
            T::try_from_bytes_mut(data).unwrap()
        }))
    }
}

pub trait AccountValidation {
    fn assert<F>(&self, condition: F) -> Result<&Self, ProgramError>
    where
        F: Fn(&Self) -> bool;

    fn assert_err<F, E>(&self, condition: F, err: E) -> Result<&Self, ProgramError>
    where
        F: Fn(&Self) -> bool,
        E: Into<ProgramError>;

    fn assert_mut<F>(&mut self, condition: F) -> Result<&mut Self, ProgramError>
    where
        F: Fn(&Self) -> bool;

    fn assert_mut_err<F, E>(&mut self, condition: F, err: E) -> Result<&mut Self, ProgramError>
    where
        F: Fn(&Self) -> bool,
        E: Into<ProgramError>;
}
