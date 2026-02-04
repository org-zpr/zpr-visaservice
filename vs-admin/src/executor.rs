//! "Executes" all the commands kicked off in main (except gui).

use std::fs::File;
use std::io::Read;
use std::io::prelude::*;
use std::path::Path;
use std::time::Duration;

use base64::prelude::*;
use colored::Colorize;
use flate2::Compression;
use flate2::write::GzEncoder;
use reqwest;
use reqwest::tls::Certificate;

use admin_api_types::admin_api_types::reason_for;
use admin_api_types::admin_api_types::{
    ActorDescriptor, AuthRevokeDescriptor, CnEntry, ListEntry, PolicyBundle, Revokes,
    ServiceDescriptor, VisaDescriptor,
};

pub struct Executor {
    api_url: String,
    cert: Certificate,
}

impl Executor {
    pub fn new(api_url: String, cert: Certificate) -> Self {
        Executor { api_url, cert }
    }

    pub fn do_cmd_policies(
        &self,
        id: Option<u64>,
        version: Option<String>,
        path: Option<String>,
        curr: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match id {
            // GET /admin/policies/{ID}
            Some(id) => self.get_policy(id)?,

            // GET /admin/policies
            None => match curr {
                true => self.get_curr_policy()?,
                false => match (version, path) {
                    (Some(version), Some(path)) => {
                        self.install_policy(version.as_str(), Path::new(&path))?
                    }
                    _ => self.get_policies()?,
                },
            },
        }
        Ok(())
    }

    pub fn do_cmd_visas(
        &self,
        id: Option<u64>,
        revoke: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match id {
            Some(id) => match revoke {
                // DELETE /admin/visas/{ID}
                true => self.revoke_visa(id)?,
                // GET /admin/visas/{ID}
                false => self.get_visa(id)?,
            },
            // GET /admin/visas
            None => self.get_visas()?,
        }
        Ok(())
    }

    pub fn do_cmd_actors(
        &self,
        cn: Option<u64>,
        revoke: bool,
        nodes: bool,
        visas: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match cn {
            Some(cn) => match (revoke, visas) {
                // DELETE /admin/actors/{CN}
                (true, _) => self.revoke_actor(cn)?,
                // GET /admin/actors/{CN}/visas
                (_, true) => self.get_related_visas(cn)?,
                // GET /admin/actors/{CN}
                _ => self.get_actor(cn)?,
            },
            // GET /admin/actors and GET /admin/actors?role=node
            None => self.get_actors(nodes)?,
        }

        Ok(())
    }

    pub fn do_cmd_services(&self, id: Option<u64>) -> Result<(), Box<dyn std::error::Error>> {
        match id {
            // GET /admin/services/{ID}
            Some(id) => self.get_service(id)?,
            // GET /admin/services
            None => self.get_services()?,
        }
        Ok(())
    }

    pub fn do_cmd_auth_revoke(
        &self,
        clear: bool,
        add: bool,
        remove: bool,
        id: Option<u64>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match id {
            Some(id) => match remove {
                true => self.remove_revoke(id)?,
                false => match add {
                    false => self.get_revoke(id)?,
                    true => self.add_revoke(id)?,
                },
            },
            None => match clear {
                true => self.clear_revokes()?,
                false => self.get_revokes()?,
            },
        }

        Ok(())
    }

    pub fn request_get_list_entries<T>(
        &self,
        req_uri: &str,
    ) -> Result<Vec<T>, Box<dyn std::error::Error>>
    where
        T: serde::de::DeserializeOwned + std::fmt::Display,
    {
        let cb = reqwest::blocking::ClientBuilder::new()
            .add_root_certificate(self.cert.clone())
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

        let entries: Vec<T> = resp.json()?;

        for (i, entry) in entries.iter().enumerate() {
            println!("{} {entry}", format!("ENTRY {}", i).bold());
        }

        Ok(entries)
    }

    fn get_policies(&self) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self
            .request_get_list_entries::<ListEntry>(&format!("{}/admin/policies", self.api_url))?;
        Ok(())
    }

    fn get_policy(&self, id: u64) -> Result<(), Box<dyn std::error::Error>> {
        let cb = reqwest::blocking::ClientBuilder::new()
            .add_root_certificate(self.cert.clone())
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10));
        let client = cb.build()?;

        let resp = client
            .get(format!("{}/admin/policies/{}", self.api_url, id))
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

    fn get_curr_policy(&self) -> Result<(), Box<dyn std::error::Error>> {
        let cb = reqwest::blocking::ClientBuilder::new()
            .add_root_certificate(self.cert.clone())
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10));
        let client = cb.build()?;

        let resp = client
            .get(format!("{}/admin/policies/curr", self.api_url))
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

    // Push a binary policy file to the visa service.
    //
    // TODO: Ideally we would open the policy file and read the version from it.  The version
    // passed here through the API is only used to catch potential problems early. The
    // visa service will open the policy file and check the actual version itself.
    //
    fn install_policy(
        &self,
        compiler_version: &str,
        policy: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cb = reqwest::blocking::ClientBuilder::new()
            .add_root_certificate(self.cert.clone())
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
            .post(format!("{}/admin/policies", self.api_url))
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

    fn get_visas(&self) -> Result<(), Box<dyn std::error::Error>> {
        let _ =
            self.request_get_list_entries::<ListEntry>(&format!("{}/admin/visas", self.api_url))?;
        Ok(())
    }

    fn get_visa(&self, id: u64) -> Result<(), Box<dyn std::error::Error>> {
        let cb = reqwest::blocking::ClientBuilder::new()
            .add_root_certificate(self.cert.clone())
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10));
        let client = cb.build()?;

        let resp = client
            .get(&format!("{}/admin/visas/{}", self.api_url, id))
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

    fn revoke_visa(&self, id: u64) -> Result<(), Box<dyn std::error::Error>> {
        let cb = reqwest::blocking::ClientBuilder::new()
            .add_root_certificate(self.cert.clone())
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10));
        let client = cb.build()?;

        let resp = client
            .delete(format!("{}/admin/visas/{}", self.api_url, id))
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

    fn get_actors(&self, nodes: bool) -> Result<(), Box<dyn std::error::Error>> {
        let query = match nodes {
            true => "?role=node",
            false => "",
        };
        let _ = self.request_get_list_entries::<CnEntry>(&format!(
            "{}/admin/actors{}",
            self.api_url, query
        ))?;
        Ok(())
    }

    fn get_actor(&self, cn: u64) -> Result<(), Box<dyn std::error::Error>> {
        let cb = reqwest::blocking::ClientBuilder::new()
            .add_root_certificate(self.cert.clone())
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10));
        let client = cb.build()?;

        let resp = client
            .get(format!("{}/admin/actors/{}", self.api_url, cn))
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

    fn revoke_actor(&self, cn: u64) -> Result<(), Box<dyn std::error::Error>> {
        let cb = reqwest::blocking::ClientBuilder::new()
            .add_root_certificate(self.cert.clone())
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10));
        let client = cb.build()?;

        let resp = client
            .delete(format!("{}/admin/actors/{}", self.api_url, cn))
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

    fn get_related_visas(&self, cn: u64) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self.request_get_list_entries::<ListEntry>(&format!(
            "{}/admin/actors/{}/visas",
            self.api_url, cn
        ))?;
        Ok(())
    }

    fn get_services(&self) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self
            .request_get_list_entries::<ListEntry>(&format!("{}/admin/services", self.api_url))?;
        Ok(())
    }

    fn get_service(&self, id: u64) -> Result<(), Box<dyn std::error::Error>> {
        let cb = reqwest::blocking::ClientBuilder::new()
            .add_root_certificate(self.cert.clone())
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10));
        let client = cb.build()?;

        let resp = client
            .get(format!("{}/admin/services/{}", self.api_url, id))
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

    fn get_revokes(&self) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self
            .request_get_list_entries::<ListEntry>(&format!("{}/admin/authrevoke", self.api_url))?;
        Ok(())
    }

    fn get_revoke(&self, id: u64) -> Result<(), Box<dyn std::error::Error>> {
        let cb = reqwest::blocking::ClientBuilder::new()
            .add_root_certificate(self.cert.clone())
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10));
        let client = cb.build()?;

        let resp = client
            .get(format!("{}/admin/authrevoke/{}", self.api_url, id))
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

    fn clear_revokes(&self) -> Result<(), Box<dyn std::error::Error>> {
        let cb = reqwest::blocking::ClientBuilder::new()
            .add_root_certificate(self.cert.clone())
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10));
        let client = cb.build()?;

        let resp = client
            .post(format!("{}/admin/authrevoke/clear", self.api_url))
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

    fn remove_revoke(&self, id: u64) -> Result<(), Box<dyn std::error::Error>> {
        let cb = reqwest::blocking::ClientBuilder::new()
            .add_root_certificate(self.cert.clone())
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10));
        let client = cb.build()?;

        let resp = client
            .delete(format!("{}/admin/authrevoke/{}", self.api_url, id))
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
    fn add_revoke(&self, id: u64) -> Result<(), Box<dyn std::error::Error>> {
        let cb = reqwest::blocking::ClientBuilder::new()
            .add_root_certificate(self.cert.clone())
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10));
        let client = cb.build()?;

        let resp = client
            .post(format!("{}/admin/authrevoke/{}", self.api_url, id))
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
}
