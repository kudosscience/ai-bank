//! Node data-directory resolution: `$CLAWBANK_HOME` or `~/.clawbank`.

use std::io;
use std::path::PathBuf;

/// The operator's home directory, or an error in hermetic environments
/// where no home variable is set.
fn home_dir() -> io::Result<PathBuf> {
    #[cfg(windows)]
    let home: Option<PathBuf> = std::env::var("USERPROFILE")
        .map(PathBuf::from)
        .ok()
        .or_else(|| {
            let drive = std::env::var("HOMEDRIVE").ok()?;
            let path = std::env::var("HOMEPATH").ok()?;
            Some(PathBuf::from(format!("{drive}{path}")))
        });
    #[cfg(windows)]
    return home
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "home directory is not set"));
    #[cfg(unix)]
    return std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "home directory is not set"));
}

/// The node data directory: `$CLAWBANK_HOME` when set (operators and
/// tests), otherwise a `.clawbank` folder under the user's home.
pub fn data_dir() -> io::Result<PathBuf> {
    match std::env::var("CLAWBANK_HOME") {
        Ok(dir) => Ok(PathBuf::from(dir)),
        Err(_) => home_dir().map(|home| home.join(".clawbank")),
    }
}

/// The identity file inside [`data_dir`].
pub fn identity_file() -> io::Result<PathBuf> {
    data_dir().map(|dir| dir.join("identity.key"))
}

/// The local petname address book inside [`data_dir`].
///
/// Plain JSON, never leaves the machine: aliases are per-node local state
/// only, never broadcast, replicated, or trusted from the network.
pub fn peers_file() -> io::Result<PathBuf> {
    data_dir().map(|dir| dir.join("peers.json"))
}
