use pinocchio::pubkey::Pubkey;
use pinocchio_pubkey::pubkey;

pub const SYSVAR_PROGRAM_ID: Pubkey = pubkey!("Sysvar1111111111111111111111111111111111111");

/// Fixed discriminator for the `EmitEvent` instruction.
pub const EMIT_EVENT_DISCRIMINATOR: u8 = 255;

// Actual limit is 10KB, but `sol_return_data` buffer is 1024 bytes long
// and 1 byte is used for the discriminator
pub const MAX_CPI_INSTRUCTION_DATA_LEN: usize = 1024 - 1;
