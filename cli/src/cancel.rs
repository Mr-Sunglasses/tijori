//! Ctrl+C during a long operation cancels it cleanly: no partly decrypted
//! file is left behind and the vault lock is released. At any other time it
//! exits as usual.

use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};

static BUSY: AtomicBool = AtomicBool::new(false);
static CANCELLED: AtomicBool = AtomicBool::new(false);
static INSTALL: Once = Once::new();

/// While alive, Ctrl+C asks the operation to stop instead of exiting.
pub struct Busy(());

pub fn busy() -> Busy {
    INSTALL.call_once(|| {
        // Fails only if a handler is already set, which `mount` does in a
        // different process path; then Ctrl+C simply keeps its old meaning.
        let _ = ctrlc::set_handler(|| {
            if BUSY.load(Ordering::SeqCst) {
                CANCELLED.store(true, Ordering::SeqCst);
            } else {
                std::process::exit(130);
            }
        });
    });
    CANCELLED.store(false, Ordering::SeqCst);
    BUSY.store(true, Ordering::SeqCst);
    Busy(())
}

impl Drop for Busy {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::SeqCst);
    }
}

/// Whether the user pressed Ctrl+C since the operation started.
pub fn requested() -> bool {
    CANCELLED.load(Ordering::SeqCst)
}
