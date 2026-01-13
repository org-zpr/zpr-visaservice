use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about = "Visa Service Admin Tool", long_about = None)]
pub struct Cmd {
    #[command(subcommand)]
    pub command: Option<SubCmd>,
    /// The visa service base API url without any final slash, eg "https://[fd5a:5052::1]:8182".
    #[arg(short, long, value_name = "URL")]
    pub svc_url: String,

    /// Path to the CA certificate file used to validate the visa service TLS credentials.
    #[arg(short, long, value_name = "PEM_CERT_FILE")]
    pub ca_cert: PathBuf,
}

#[derive(Subcommand)]
pub enum SubCmd {
    /// List installed policies
    #[command()]
    Policies {
        /// If id is supplied, list only policy with matching ID
        #[arg(long)]
        id: Option<u64>,
    },

    //
    #[command()]
    Policy {
        /// Shows the current policy
        #[arg(long, short = 'v')]
        version: Option<String>,
        #[arg(long, short = 'p')]
        path: Option<String>,
    },

    /// List visas
    #[command()]
    Visas {
        /// If id is supplied, list only visa with matching ID
        #[arg(long)]
        id: Option<u64>,
        /// If revoke is true, ID must be supplied, and instead of returning the visa info, it is revoked
        // TODO decide if it should be visas --revoke --id ID or if revoke should also take a u64 and be visas --revoke ID
        #[arg(long, short = 'r')]
        revoke: bool,
    },

    /// List actors
    #[command()]
    Actors {
        /// If id is supplied, list only visa with matching ID
        #[arg(long)]
        id: Option<u64>,
        /// If revoke is true, ID must be supplied, and instead of returning the actor info, the actor is removed (along with all associated visas)
        // TODO decide if it should be visas --revoke --id ID or if revoke should also take a u64 and be visas --revoke ID
        #[arg(long, short = 'r')]
        revoke: bool,
        /// If node is true, then it will only return the node actors
        #[arg(long, short = 'n')]
        nodes: bool,
        /// If visas is true, ID must be supplied, and return the visa IDs related to the actor
        /// Can be used in conjunction with nodes
        #[arg(long, short = 'v')]
        visas: bool,
    },

    /// List services
    #[command()]
    Services {
        /// If id is supplied, list only service with matching ID
        #[arg(long)]
        id: Option<u64>,
    },

    // /// Install a policy from a compiled policy file
    // #[command()]
    // Install {
    //     /// Version of the ZPL compiler used to compile the policy.
    //     #[arg(short = 'c', long, value_name = "X.Y.Z")]
    //     compiler_version: String,

    //     #[arg(short, long, value_name = "POLICY_FILE")]
    //     policy: PathBuf,
    // },
    /// Clear revoke state in visa service
    #[command()]
    AuthRevoke {
        #[arg(long, short = 'c')]
        clear: bool,

        #[arg(long, short = 'a')]
        add: bool,

        #[arg(long, short = 'r')]
        remove: bool,

        #[arg(long)]
        id: Option<u64>,
    },

    /// Enter GUI mode
    #[command()]
    Gui,
}
