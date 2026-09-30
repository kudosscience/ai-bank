//! ClawBank node CLI. Agents use the local HTTP/MCP interface (ADR-0003);
//! this binary is the human operator surface.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "clawbank", about = "ClawBank node: banking for LLM agents")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate the node identity on first run, then print its PeerId.
    Init,
    /// Print the node identity as portable text for offline backup.
    ///
    /// Store the output somewhere safe: lose both the identity file and
    /// this export and the PeerId is unrecoverable by design (ADR-0001).
    Export,
    /// Restore the node identity from an `export` backup.
    ///
    /// The export is validated before anything is written, so malformed
    /// material fails without touching the existing identity. Lose both
    /// the identity file and the export and the PeerId is unrecoverable
    /// by design (ADR-0001).
    Import {
        /// Export text from `clawbank export`; reads stdin when omitted.
        export: Option<String>,
    },
    /// Local petname address book: human-readable aliases for known PeerIds.
    ///
    /// Aliases are per-node local state only (peers.json inside the data
    /// directory): never broadcast, replicated, or trusted from the
    /// network. The full PeerId is always shown beside the alias, and no
    /// command accepts an alias where a PeerId is required.
    Peer {
        #[command(subcommand)]
        action: PeerCommands,
    },
}

#[derive(Subcommand)]
enum PeerCommands {
    /// Store (or update) the local alias for a PeerId.
    Add {
        /// Canonical PeerId (base58 `12D3Koo…` or CID `bafz…`); an alias is rejected.
        peer_id: String,
        /// Human-readable alias (1-64 chars, no surrounding whitespace, never a PeerId).
        alias: String,
    },
    /// Show every known peer as `alias (short PeerId) full-PeerId`.
    List,
}

fn print_peer_id(keypair: &clawbank_identity::Keypair) {
    let id = clawbank_identity::peer_id(keypair);
    println!(
        "Peer ID (base58): {}",
        clawbank_identity::peer_id_base58(&id)
    );
    println!("Peer ID (CID): {}", clawbank_identity::peer_id_cid(&id));
}

fn run_export() -> std::io::Result<()> {
    let path = clawbank_identity::identity_file()?;
    let keypair = clawbank_identity::load(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no identity found, run `clawbank init` first",
            )
        } else {
            e
        }
    })?;
    // Stdout carries only the portable export so `export > backup.txt`
    // captures exactly what `import` expects.
    println!("{}", clawbank_identity::export(&keypair)?);
    Ok(())
}

fn run_import(export: Option<String>) -> std::io::Result<()> {
    let material = match export {
        Some(text) => text,
        None => read_bounded_stdin()?,
    };
    let keypair = clawbank_identity::import(&material, &clawbank_identity::identity_file()?)?;
    print_peer_id(&keypair);
    Ok(())
}

/// Read the piped export from stdin, bounded so a large or never-ending
/// stream cannot exhaust memory before validation. A valid export is
/// ~100 bytes; the cap leaves orders of magnitude of headroom.
fn read_bounded_stdin() -> std::io::Result<String> {
    const MAX_STDIN_EXPORT_BYTES: usize = 64 * 1024;
    let stdin = std::io::stdin();
    let mut limited = std::io::Read::take(stdin, MAX_STDIN_EXPORT_BYTES as u64 + 1);
    let mut buf = String::new();
    std::io::Read::read_to_string(&mut limited, &mut buf)?;
    if buf.len() > MAX_STDIN_EXPORT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a valid identity export: input too large",
        ));
    }
    Ok(buf)
}

fn run_peer_add(peer_id: &str, alias: &str) -> std::io::Result<()> {
    // Strict PeerId parsing: an alias never substitutes for identity.
    let id = clawbank_identity::parse_peer_id(peer_id)?;
    clawbank_identity::set_alias(&clawbank_identity::peers_file()?, &id, alias)?;
    // The alias is echoed only beside its PeerId, never alone.
    println!(
        "{} {}",
        clawbank_identity::display_peer(Some(alias), &id),
        clawbank_identity::peer_id_base58(&id)
    );
    Ok(())
}

fn run_peer_list() -> std::io::Result<()> {
    let mut book: Vec<_> = clawbank_identity::aliases(&clawbank_identity::peers_file()?)?
        .into_iter()
        .collect();
    // Stable, human-friendly order: alias first, then identity.
    book.sort_by(|a, b| {
        a.1.cmp(&b.1).then_with(|| {
            clawbank_identity::peer_id_base58(&a.0).cmp(&clawbank_identity::peer_id_base58(&b.0))
        })
    });
    for (id, alias) in &book {
        println!(
            "{} {}",
            clawbank_identity::display_peer(Some(alias), id),
            clawbank_identity::peer_id_base58(id)
        );
    }
    Ok(())
}

fn run() -> std::io::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init => {
            let keypair =
                clawbank_identity::load_or_generate(&clawbank_identity::identity_file()?)?;
            print_peer_id(&keypair);
            Ok(())
        }
        Commands::Export => run_export(),
        Commands::Import { export } => run_import(export),
        Commands::Peer { action } => match action {
            PeerCommands::Add { peer_id, alias } => run_peer_add(&peer_id, &alias),
            PeerCommands::List => run_peer_list(),
        },
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
