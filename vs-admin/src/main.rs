mod gui;
mod main_args;

use std::fs::File;
use std::io::Read;
use std::io::prelude::*;
use std::path::Path;
use std::time::Duration;

use base64::prelude::*;
use clap::{Args, Parser};
use colored::Colorize;
use flate2::Compression;
use flate2::write::GzEncoder;
use reqwest;
use reqwest::tls::Certificate;

use admin_api_types::admin_api_types::reason_for;
use admin_api_types::admin_api_types::{
    ActorDescriptor, AuthRevokeDescriptor, ListEntry, PolicyBundle, Revokes, ServiceDescriptor,
    VisaDescriptor,
};

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

    match args.command {
        Some(SubCmd::Policies { id }) => match id {
            // GET /admin/policies/{ID}
            Some(id) => get_policy(&args.svc_url, ca_cert, id),
            // GET /admin/policies
            None => get_policies(&args.svc_url, ca_cert),
        }
        .unwrap_or_else(|e| {
            eprintln!("{} {}", "Error: ".red(), e);
        }),
        Some(SubCmd::Policy { version, path }) => match (version, path) {
            // POST /admin/policy
            (Some(version), Some(path)) => {
                install_policy(&args.svc_url, ca_cert, version.as_str(), Path::new(&path))
            }
            // GET /admin/policy
            (None, None) => get_curr_policy(&args.svc_url, ca_cert),
            _ => Err("Both version and path must be set to install a policy".into()).into(),
        }
        .unwrap_or_else(|e| {
            eprintln!("{} {}", "Error: ".red(), e);
        }),
        Some(SubCmd::Visas { id, revoke }) => match id {
            Some(id) => match revoke {
                // DELETE /admin/visas/{ID}
                true => revoke_visa(&args.svc_url, ca_cert, id),
                // GET /admin/visas/{ID}
                false => get_visa(&args.svc_url, ca_cert, id),
            },
            // GET /admin/visas
            None => get_visas(&args.svc_url, ca_cert),
        }
        .unwrap_or_else(|e| {
            eprintln!("{} {}", "Error: ".red(), e);
        }),
        Some(SubCmd::Actors {
            id,
            revoke,
            nodes,
            visas,
        }) => match id {
            Some(id) => match (revoke, visas) {
                // DELETE /admin/actors/{CN}
                (true, _) => revoke_actor(&args.svc_url, ca_cert, id),
                // GET /admin/actors/{CN}/visas
                (_, true) => get_related_visas(&args.svc_url, ca_cert, id),
                // GET /admin/actors/{CN}
                _ => get_actor(&args.svc_url, ca_cert, id),
            },
            // GET /admin/actors and GET /admin/actors?role=node
            None => get_actors(&args.svc_url, ca_cert, nodes),
        }
        .unwrap_or_else(|e| {
            eprintln!("{} {}", "Error: ".red(), e);
        }),
        Some(SubCmd::Services { id }) => match id {
            // GET /admin/services/{ID}
            Some(id) => get_service(&args.svc_url, ca_cert, id),
            // GET /admin/services
            None => get_services(&args.svc_url, ca_cert),
        }
        .unwrap_or_else(|e| {
            eprintln!("{} {}", "Error: ".red(), e);
        }),
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
        }) => match id {
            Some(id) => match remove {
                true => remove_revoke(&args.svc_url, ca_cert, id),
                false => match add {
                    false => get_revoke(&args.svc_url, ca_cert, id),
                    true => add_revoke(&args.svc_url, ca_cert, id),
                },
            },
            None => match clear {
                true => clear_revokes(&args.svc_url, ca_cert),
                false => get_revokes(&args.svc_url, ca_cert),
            },
        }
        .unwrap_or_else(|e| {
            eprintln!("{} {}", "Error: ".red(), e);
        }),

        Some(SubCmd::Gui) => {
            gui::enter_gui(&args.svc_url, ca_cert).unwrap_or_else(|e| {
                eprintln!("{} {}", "Error: ".red(), e);
            });
        }
        None => {
            println!("{}", "No command specified".red());
        }
    }
}

fn load_cert(ca: &Path) -> Result<Certificate, Box<dyn std::error::Error>> {
    let mut cert_buf = Vec::new();
    File::open(ca)?.read_to_end(&mut cert_buf)?;
    let cert = Certificate::from_pem(&cert_buf)?;
    Ok(cert)
}

pub fn request_get_list_entry(
    cert: Certificate,
    req_uri: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let cb = reqwest::blocking::ClientBuilder::new()
        .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));
    let client = cb.build()?;

    let resp = client.get(req_uri).send()?;
    if !resp.status().is_success() {
        return Err(format!(
            "error (status {:?}:{}) : {}",
            resp.status(),
            reason_for(resp.status()),
            resp.text()?
        )
        .into());
    }

    let entries: Vec<ListEntry> = resp.json()?;

    for (i, entry) in entries.iter().enumerate() {
        println!("{} {entry}", format!("ENTRY {}", i).bold());
    }

    Ok(())
}

fn get_policies(api_url: &str, cert: Certificate) -> Result<(), Box<dyn std::error::Error>> {
    request_get_list_entry(cert, format!("{}/admin/policies", api_url))
}

fn get_policy(api_url: &str, cert: Certificate, id: u64) -> Result<(), Box<dyn std::error::Error>> {
    let cb = reqwest::blocking::ClientBuilder::new()
        .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));
    let client = cb.build()?;

    let resp = client
        .get(format!("{}/admin/policies/{}", api_url, id))
        .send()?;
    if !resp.status().is_success() {
        return Err(format!(
            "error (status {:?}:{}) : {}",
            resp.status(),
            reason_for(resp.status()),
            resp.text()?
        )
        .into());
    }

    let entry: PolicyBundle = resp.json()?;
    println!("{entry}");

    Ok(())
}

fn get_curr_policy(api_url: &str, cert: Certificate) -> Result<(), Box<dyn std::error::Error>> {
    let cb = reqwest::blocking::ClientBuilder::new()
        .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));
    let client = cb.build()?;

    let resp = client.get(format!("{}/admin/policy", api_url)).send()?;
    if !resp.status().is_success() {
        return Err(format!(
            "error (status {:?}:{}) : {}",
            resp.status(),
            reason_for(resp.status()),
            resp.text()?
        )
        .into());
    }

    let entry: PolicyBundle = resp.json()?;
    println!("{entry}");

    Ok(())
}

// Push a binary policy file to the visa service.
//
// TODO: Ideally we would open the policy file and read the version from it.  The version
// passed here through the API is only used to catch potential problems early. The
// visa service will open the policy file and check the actual version itself.
//
fn install_policy(
    api_url: &str,
    cert: Certificate,
    compiler_version: &str,
    policy: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let cb = reqwest::blocking::ClientBuilder::new()
        .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));
    let client = cb.build()?;

    let mut policy_buf = Vec::new();
    File::open(policy)?.read_to_end(&mut policy_buf)?;

    let raw_len = policy_buf.len();

    // compress policy data with gzip
    let mut gz_w = GzEncoder::new(Vec::new(), Compression::default());
    gz_w.write_all(&policy_buf)?;
    let gz_bytes = gz_w.finish()?;

    let gz_len = gz_bytes.len();

    // encode the compressed data as base64
    let container = BASE64_STANDARD.encode(&gz_bytes);

    println!(
        "{}",
        format!(
            "sending policy: container size {} bytes (raw {} / {} compressed)",
            container.len(),
            raw_len,
            gz_len
        )
        .magenta()
    );

    let bundle = PolicyBundle {
        config_id: 0,
        version: "".to_string(),
        format: format!("base64;zip;{}", compiler_version),
        container,
    };

    let resp = client
        .post(format!("{}/admin/policy", api_url))
        .json(&bundle)
        .send()?;

    if !resp.status().is_success() {
        return Err(format!(
            "error (status {:?}:{}) : {}",
            resp.status(),
            reason_for(resp.status()),
            resp.text()?
        )
        .into());
    }

    let entry: ListEntry = resp.json()?;

    println!("{entry}");

    Ok(())
}

fn get_visas(api_url: &str, cert: Certificate) -> Result<(), Box<dyn std::error::Error>> {
    request_get_list_entry(cert, format!("{}/admin/visas", api_url))
}

fn get_visa(api_url: &str, cert: Certificate, id: u64) -> Result<(), Box<dyn std::error::Error>> {
    let cb = reqwest::blocking::ClientBuilder::new()
        .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));
    let client = cb.build()?;

    let resp = client
        .get(format!("{}/admin/visas/{}", api_url, id))
        .send()?;
    if !resp.status().is_success() {
        return Err(format!(
            "error (status {:?}:{}) : {}",
            resp.status(),
            reason_for(resp.status()),
            resp.text()?
        )
        .into());
    }

    let entry: VisaDescriptor = resp.json()?;
    println!("{entry}");

    Ok(())
}

fn revoke_visa(
    api_url: &str,
    cert: Certificate,
    id: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let cb = reqwest::blocking::ClientBuilder::new()
        .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));
    let client = cb.build()?;

    let resp = client
        .delete(format!("{}/admin/visas/{}", api_url, id))
        .send()?;
    if !resp.status().is_success() {
        return Err(format!(
            "error (status {:?}:{}) : {}",
            resp.status(),
            reason_for(resp.status()),
            resp.text()?
        )
        .into());
    }

    let revoke: Revokes = resp.json()?;
    println!("{revoke}");

    Ok(())
}

fn get_actors(
    api_url: &str,
    cert: Certificate,
    nodes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let query = match nodes {
        true => "?role=node",
        false => "",
    };

    request_get_list_entry(cert, format!("{}/admin/actors{}", api_url, query))
}

fn get_actor(api_url: &str, cert: Certificate, id: u64) -> Result<(), Box<dyn std::error::Error>> {
    let cb = reqwest::blocking::ClientBuilder::new()
        .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));
    let client = cb.build()?;

    let resp = client
        .get(format!("{}/admin/actors/{}", api_url, id))
        .send()?;
    if !resp.status().is_success() {
        return Err(format!(
            "error (status {:?}:{}) : {}",
            resp.status(),
            reason_for(resp.status()),
            resp.text()?
        )
        .into());
    }

    let entry: ActorDescriptor = resp.json()?;
    println!("{entry}");

    Ok(())
}

fn revoke_actor(
    api_url: &str,
    cert: Certificate,
    id: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let cb = reqwest::blocking::ClientBuilder::new()
        .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));
    let client = cb.build()?;

    let resp = client
        .delete(format!("{}/admin/actors/{}", api_url, id))
        .send()?;
    if !resp.status().is_success() {
        return Err(format!(
            "error (status {:?}:{}) : {}",
            resp.status(),
            reason_for(resp.status()),
            resp.text()?
        )
        .into());
    }

    let revoke: Revokes = resp.json()?;
    println!("{revoke}");

    Ok(())
}

fn get_related_visas(
    api_url: &str,
    cert: Certificate,
    id: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    request_get_list_entry(cert, format!("{}/admin/actors/{}/visas", api_url, id))
}

fn get_services(api_url: &str, cert: Certificate) -> Result<(), Box<dyn std::error::Error>> {
    request_get_list_entry(cert, format!("{}/admin/services", api_url))
}

fn get_service(
    api_url: &str,
    cert: Certificate,
    id: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let cb = reqwest::blocking::ClientBuilder::new()
        .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));
    let client = cb.build()?;

    let resp = client
        .get(format!("{}/admin/services/{}", api_url, id))
        .send()?;
    if !resp.status().is_success() {
        return Err(format!(
            "error (status {:?}:{}) : {}",
            resp.status(),
            reason_for(resp.status()),
            resp.text()?
        )
        .into());
    }

    let entry: ServiceDescriptor = resp.json()?;
    println!("{entry}");

    Ok(())
}

fn get_revokes(api_url: &str, cert: Certificate) -> Result<(), Box<dyn std::error::Error>> {
    request_get_list_entry(cert, format!("{}/admin/authrevoke", api_url))
}

fn get_revoke(api_url: &str, cert: Certificate, id: u64) -> Result<(), Box<dyn std::error::Error>> {
    let cb = reqwest::blocking::ClientBuilder::new()
        .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));
    let client = cb.build()?;

    let resp = client
        .get(format!("{}/admin/authrevoke/{}", api_url, id))
        .send()?;
    if !resp.status().is_success() {
        return Err(format!(
            "error (status {:?}:{}) : {}",
            resp.status(),
            reason_for(resp.status()),
            resp.text()?
        )
        .into());
    }

    let entry: AuthRevokeDescriptor = resp.json()?;
    println!("{entry}");

    Ok(())
}

fn clear_revokes(api_url: &str, cert: Certificate) -> Result<(), Box<dyn std::error::Error>> {
    let cb = reqwest::blocking::ClientBuilder::new()
        .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));
    let client = cb.build()?;

    let resp = client
        .post(format!("{}/admin/authrevoke/clear", api_url))
        .send()?;
    if !resp.status().is_success() {
        return Err(format!(
            "error (status {:?}:{}) : {}",
            resp.status(),
            reason_for(resp.status()),
            resp.text()?
        )
        .into());
    }

    let entries: Vec<ListEntry> = resp.json()?;

    for (i, entry) in entries.iter().enumerate() {
        println!("{} {entry}", format!("ENTRY {}", i).bold());
    }

    Ok(())
}

fn remove_revoke(
    api_url: &str,
    cert: Certificate,
    id: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let cb = reqwest::blocking::ClientBuilder::new()
        .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));
    let client = cb.build()?;

    let resp = client
        .delete(format!("{}/admin/authrevoke/{}", api_url, id))
        .send()?;
    if !resp.status().is_success() {
        return Err(format!(
            "error (status {:?}:{}) : {}",
            resp.status(),
            reason_for(resp.status()),
            resp.text()?
        )
        .into());
    }

    let entry: ListEntry = resp.json()?;

    println!("{entry}");

    Ok(())
}

// TODO figure out how we want to get the visa information from the user.
// Some options would be take in a file with a JSON VisaDescriptor or take in
// the parts we care about via arguments on the command line
fn add_revoke(api_url: &str, cert: Certificate, id: u64) -> Result<(), Box<dyn std::error::Error>> {
    let cb = reqwest::blocking::ClientBuilder::new()
        .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10));
    let client = cb.build()?;

    let resp = client
        .post(format!("{}/admin/authrevoke/{}", api_url, id))
        .send()?;

    if !resp.status().is_success() {
        return Err(format!(
            "error (status {:?}:{}) : {}",
            resp.status(),
            reason_for(resp.status()),
            resp.text()?
        )
        .into());
    }

    let entry: ListEntry = resp.json()?;

    println!("{entry}");

    Ok(())
}
