mod error;
mod executor;
mod gui;
mod main_args;
mod vsclient;

use std::fs::File;
use std::io::Read;
use std::path::Path;

use clap::{Args, Parser};
use colored::Colorize;
use reqwest;
use reqwest::tls::Certificate;

use crate::executor::Executor;
use crate::main_args::{Cmd, SubCmd};

#[derive(Args)]
#[group(required = true, multiple = false)]
struct RevokeArg {
    /// Revoke a visa ID
    #[arg(long)]
    visa_id: Option<u64>,

    /// Revoke access to a given adapter CN
    #[arg(long)]
    actor_cn: Option<String>,
}

fn main() {
    let args = Cmd::parse();

    let ca_cert = load_cert(&args.ca_cert).unwrap();

    let exec = Executor::new(args.svc_url.clone(), ca_cert.clone());

    match args.command {
        Some(SubCmd::Policies {
            id,
            version,
            path,
            curr,
        }) => exec.do_cmd_policies(id, version, path, curr),

        Some(SubCmd::Visas { id, revoke }) => exec.do_cmd_visas(id, revoke),

        Some(SubCmd::Actors {
            cn,
            revoke,
            nodes,
            visas,
        }) => exec.do_cmd_actors(cn, revoke, nodes, visas),

        Some(SubCmd::Services { id }) => exec.do_cmd_services(id),
        // Some(SubCmd::Install {
        //     compiler_version,
        //     policy,
        // }) => install(&args.svc_url, ca_cert, &compiler_version, &policy).unwrap_or_else(|e| {
        //     eprintln!("{} {}", "Error: ".red(), e);
        // }),
        Some(SubCmd::AuthRevoke {
            clear,
            add,
            remove,
            id,
        }) => exec.do_cmd_auth_revoke(clear, add, remove, id),

        Some(SubCmd::Gui) => gui::enter_gui(&args.svc_url, ca_cert),

        None => Err("no command specified".into()),
    }
    .unwrap_or_else(|e| {
        eprintln!("{} {}", "Error: ".red(), e);
    })
}

fn load_cert(ca: &Path) -> Result<Certificate, Box<dyn std::error::Error>> {
    let mut cert_buf = Vec::new();
    File::open(ca)?.read_to_end(&mut cert_buf)?;
    let cert = Certificate::from_pem(&cert_buf)?;
    Ok(cert)
}
