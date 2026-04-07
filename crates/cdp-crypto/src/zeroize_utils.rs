//! Utilities for preventing credential leakage via core dumps and swap.

use nix::sys::prctl;
use nix::sys::resource::{Resource, setrlimit};

use crate::CryptoError;

/// Disable core dumps to prevent credential leakage.
///
/// Sets `PR_SET_DUMPABLE=0` so no core file is written on crash, and
/// sets `RLIMIT_CORE=0` as an additional belt-and-suspenders measure.
pub fn disable_core_dumps() -> Result<(), CryptoError> {
    prctl::set_dumpable(false)
        .map_err(|e| CryptoError::SystemCall(format!("prctl set_dumpable: {e}")))?;
    setrlimit(Resource::RLIMIT_CORE, 0, 0)
        .map_err(|e| CryptoError::SystemCall(format!("setrlimit CORE: {e}")))?;
    Ok(())
}

// Re-export zeroize traits for convenience.
pub use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disable_core_dumps() {
        // Should succeed on a standard Linux system running as an unprivileged user.
        disable_core_dumps().expect("disable_core_dumps should not fail");
    }
}
