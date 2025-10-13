use pinocchio::{
    account_info::AccountInfo,
    instruction::{AccountMeta, Instruction, Signer},
    program::{invoke_signed, set_return_data},
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};

use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer};

use crate::{EMIT_EVENT_DISCRIMINATOR, MAX_CPI_INSTRUCTION_DATA_LEN};

/// Create a new program account.
///
/// ### Accounts:
///   0. `[WRITE, SIGNER]` Funding account
///   1. `[WRITE, SIGNER]` PDA account
pub struct CreateProgramAccount<'a> {
    /// Funding account.
    pub payer: &'a AccountInfo,

    /// PDA account.
    pub pda: &'a AccountInfo,

    /// Number of bytes of memory to allocate.
    pub space: usize,

    /// Address of program that will own the new account.
    pub owner: &'a Pubkey,
}

impl CreateProgramAccount<'_> {
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    /// Create a new PDA.
    #[inline(always)]
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        if self.pda.lamports() == 0 {
            // If balance is zero, create account
            return CreateAccount {
                from: self.payer,
                to: self.pda,
                lamports: Rent::get()?.minimum_balance(self.space).max(1),
                space: self.space as u64,
                owner: self.owner,
            }
            .invoke_signed(signers);
        }
        
        // Anyone can transfer lamports to accounts before they're initialized
        // in that case, creating the account won't work.
        // in order to get around it, you need to fund the account with enough lamports to be rent exempt,
        // then allocate the required space and set the owner to the current program

        let required_lamports = Rent::get()?
            .minimum_balance(self.space)
            .max(1)
            .saturating_sub(self.pda.lamports());

        // 1) Transfer sufficient lamports for rent exemption
        if required_lamports > 0 {
            Transfer {
                from: self.payer,
                to: self.pda,
                lamports: required_lamports,
            }
            .invoke()?;
        }

        // 2) Allocate space for the account
        Allocate {
            account: self.pda,
            space: self.space as u64,
        }
        .invoke_signed(signers)?;

        // 3) Assign our program as the owner
        Assign {
            account: self.pda,
            owner: self.owner,
        }
        .invoke_signed(signers)?;


        Ok(())
    }
}

/// Resize existing program account.
///
/// ### Accounts:
///   0. `[WRITE, SIGNER]` Funding account
///   1. `[WRITE, SIGNER]` PDA account
pub struct ResizeProgramAccount<'a> {
    /// Funding account.
    pub payer: &'a AccountInfo,

    /// PDA account.
    pub pda: &'a AccountInfo,

    /// Number of bytes of memory to allocate.
    pub space: usize,

    /// Program that owns the account.
    pub program: &'a Pubkey,
}

impl ResizeProgramAccount<'_> {
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        if self.pda.owner() != self.program {
            return Err(ProgramError::IllegalOwner);
        }

        let required_lamports = Rent::get()?
            .minimum_balance(self.space)
            .max(1)
            .saturating_sub(self.pda.lamports());
            
        if required_lamports > 0 {
            Transfer { from: self.payer, to: self.pda, lamports: required_lamports}.invoke()?;
        }

        self.pda.resize(self.space)?;

        Ok(())
    }
}

/// Close a program account
///
/// Best solution, which is implemented in anchor's close constraint,
/// is to defund the account, reassign the account to the system program, and reallocate it to 0 bytes.
/// Basically doing the account creation process, but backwards!
///
/// ### Accounts:
///   0. `[WRITE]` The account to close.
///   1. `[WRITE]` The destination account.

pub struct CloseProgramAccount<'a> {
    pub account: &'a AccountInfo,
    pub destination: &'a AccountInfo,
}

impl CloseProgramAccount<'_> {
    #[inline(always)]
    pub fn invoke(&self) -> ProgramResult {
        // Defund by transferring all SOL to the destination account.
        // Use direct lamports manipulation, SystemProgram::Transfer can't work with data carrying accounts.
        *self.destination.try_borrow_mut_lamports()? += *self.account.try_borrow_lamports()?;
        *self.account.try_borrow_mut_lamports()? = 0;

        // Resize the account to 1 byte and close it
        self.account.resize(0)?;
        self.account.close()
    }
}

/// Log an event by making a self-CPI that can be subscribed to by clients.
///
/// This way of logging events is more reliable than `log` or `log_return` because RPCs are less likely
/// to truncate CPI information than program logs.
///
/// Uses a [`invoke_signed`](https://docs.rs/solana-program/latest/solana_program/program/fn.invoke_signed.html)
/// syscall to store the event data in the ledger, which results in the data being stored in the
/// transaction metadata.
///
/// This method requires the usage of an additional PDA to guarantee that the self-CPI is truly
/// being invoked by the same program. Requiring this PDA to be a signer during `invoke_signed`
/// syscall ensures that the program is the one doing the logging.
///
/// ### Accounts:
///   0. `[]` Program ID account
///   1. `[SIGNER]` Event authority account
pub struct EmitEvent<'a> {
    /// Program ID.
    pub program_id: &'a Pubkey,
    /// Program account.
    pub program: &'a AccountInfo,
    /// Event authority PDA.
    pub event_authority: &'a AccountInfo,
    /// Event data.
    pub data: &'a [u8],
}

impl EmitEvent<'_> {
    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        // Check if data length is within the limits
        if self.data.len() > MAX_CPI_INSTRUCTION_DATA_LEN || self.data.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut buf = [0; 1 + MAX_CPI_INSTRUCTION_DATA_LEN];
        buf[0] = EMIT_EVENT_DISCRIMINATOR;
        buf[1..1 + self.data.len()].copy_from_slice(self.data);

        let instruction_data =
            unsafe { core::slice::from_raw_parts(buf.as_ptr() as _, 1 + self.data.len()) };
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: &[AccountMeta::readonly_signer(self.event_authority.key())],
            data: instruction_data,
        };
        // Save in self-CPI instruction data
        invoke_signed(&instruction, &[self.event_authority, self.program], signers)?;
        Ok(())
    }
}
