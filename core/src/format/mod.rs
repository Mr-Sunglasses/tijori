//! The on-disk format (spec/SPEC.md): pure functions over bytes, no I/O.
//! Every parser enforces the §12 limits before allocating or deriving keys.

pub mod cbor;
pub mod dir;
pub mod header;
pub mod keyslot;
pub mod object;
pub mod root;

pub use dir::{DirEntry, Directory};
pub use header::Header;
pub use keyslot::{ArgonParams, Keyslot, SlotKind};
pub use object::{ObjectKind, ObjectReader, ObjectWriter};
pub use root::{RootPointer, RootSlot, Settings};
