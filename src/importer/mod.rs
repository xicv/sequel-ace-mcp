//! Sequel Ace integration (legacy `importer/` port): read the GUI's
//! queryHistory.db read-only, parse Favorites.plist into connection
//! configs, and (optionally) copy passwords from the Sequel Ace
//! Keychain entries into our secret store via `/usr/bin/security`.
//! Sequel Ace data is never modified.

pub mod history;
pub mod plist_import;

pub use history::{read_sequel_ace_history, stat_sequel_ace_history};
pub use plist_import::{import_from_sequel_ace, read_favorites_plist};
