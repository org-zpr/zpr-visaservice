use chrono::{DateTime, SecondsFormat, Utc};
use colored::{Color, Colorize};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::fmt;

/// List entry is a list with a numeric ID.
#[derive(Serialize, Deserialize)]
pub struct ListEntry {
    pub id: u64,
}

impl fmt::Display for ListEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", format!("{}", "id".dimmed()), self.id,)
    }
}

/// NamedListEntry is a list with a string ID.
#[derive(Serialize, Deserialize)]
pub struct NamedListEntry {
    pub id: String,
}

impl fmt::Display for NamedListEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", format!("{}", "id".dimmed()), self.id,)
    }
}

#[derive(Serialize, Deserialize)]
pub struct PolicyBundle {
    pub config_id: u64,  // ignored when installing
    pub version: String, // use empty string if you don't care
    pub format: String,
    pub container: String,
}

impl fmt::Display for PolicyBundle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {}, {} {}, {} {}, {} {}",
            format!("{}", "id".dimmed()),
            self.config_id,
            format!("{}", "version".dimmed()),
            self.version,
            format!("{}", "format".dimmed()),
            self.format,
            format!("{}", "container".dimmed()),
            self.container,
        )
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VisaMatchDirection {
    Forward,
    Reverse,
}

impl fmt::Display for VisaMatchDirection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VisaMatchDirection::Forward => write!(f, "forward"),
            VisaMatchDirection::Reverse => write!(f, "reverse"),
        }
    }
}

#[derive(Serialize, Debug, Deserialize, Eq)]
pub struct VisaDescriptor {
    /// Policy reported version number
    pub id: u64,
    #[serde(rename = "expires")]
    pub expires_secs: u64, // seconds since the epoch
    #[serde(rename = "created")]
    pub created_secs: u64, // seconds since the epoch
    pub policy_id: String,
    pub zpl: String,
    pub direction: VisaMatchDirection,
    pub requesting_node: String, // ZPR address
    pub source_addr: String,     // ZPR address
    pub dest_addr: String,       // ZPR address
    pub source_port: u16,
    pub dest_port: u16,
    pub proto: String,
    pub signals: Vec<String>,
}

impl PartialEq for VisaDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Ord for VisaDescriptor {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl PartialOrd for VisaDescriptor {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for VisaDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let now = Utc::now();
        let dt_exp: DateTime<Utc> = DateTime::from_timestamp(self.expires_secs as i64, 0).unwrap();
        let dt_created: DateTime<Utc> =
            DateTime::from_timestamp(self.created_secs as i64, 0).unwrap();
        let remain = dt_exp.signed_duration_since(now);

        write!(f, "{} {}", "id".dimmed(), self.id)?;
        write!(
            f,
            "  {} {}",
            "requesting node".dimmed(),
            self.requesting_node.yellow()
        )?;
        write!(f, "  {} {}", "policy id".dimmed(), self.policy_id)?;
        write!(
            f,
            "  {} [{}] {}",
            "zpl".dimmed(),
            self.direction,
            self.zpl.yellow()
        )?;
        write!(
            f,
            "  {}:{} {} {}:{}",
            self.source_addr.yellow(),
            self.source_port,
            "->".bold().green(),
            self.dest_addr.yellow(),
            self.dest_port,
        )?;
        write!(f, "  {} {}", "proto".dimmed(), self.proto)?;
        write!(
            f,
            "  {} {}",
            "created".dimmed(),
            dt_created.to_rfc3339_opts(SecondsFormat::Secs, true).cyan()
        )?;
        write!(
            f,
            "  {} {} ({}:{:02}:{:02} remain)",
            "exp".dimmed(),
            dt_exp.to_rfc3339_opts(SecondsFormat::Secs, true).cyan(),
            remain.num_hours(),
            remain.num_minutes() % 60,
            remain.num_seconds() % 60,
        )?;
        if !self.signals.is_empty() {
            write!(f, "  {} [{}]", "signals".dimmed(), self.signals.join(", "))?;
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct Revokes {
    pub id: String,
    pub revoked: Vec<u64>,
}

impl fmt::Display for Revokes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {} {:?}",
            format!("{}", "id".dimmed()),
            self.id,
            format!("{}", "revoked".dimmed()),
            self.revoked
        )
    }
}

#[derive(Debug, Serialize, Deserialize, Eq)]
pub struct ActorDescriptor {
    pub cn: String,
    #[serde(rename = "created")]
    pub ctime_secs: u64, // seconds since the epoch
    pub ident: String,
    pub node: bool,
    pub zpr_addr: String,
    pub node_details: Option<NodeRecordBrief>,
}

impl PartialEq for ActorDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.cn == other.cn
    }
}

impl Ord for ActorDescriptor {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.cn.cmp(&other.cn)
    }
}

impl PartialOrd for ActorDescriptor {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for ActorDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ts: DateTime<Utc> = DateTime::from_timestamp(self.ctime_secs as i64, 0).unwrap();
        write!(
            f,
            "{} {}{}{} @ {} {}{} {}{} {}",
            self.cn,
            "(created: ".dimmed(),
            ts.to_rfc3339_opts(SecondsFormat::Secs, true).cyan(),
            ")".dimmed(),
            self.zpr_addr.yellow(),
            "identity: ".dimmed(),
            self.ident,
            "is node: ".dimmed(),
            self.node,
            if self.node_details.is_some() {
                "[has node details]".green()
            } else {
                "".normal()
            },
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Eq)]
pub struct ServiceDescriptor {
    pub service_name: String,
    pub actor_cn: String,
    pub zpr_addr: String,
    pub dock_zpr_addr: String,
}

impl PartialEq for ServiceDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.service_name == other.service_name
    }
}

impl Ord for ServiceDescriptor {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.service_name.cmp(&other.service_name)
    }
}

impl PartialOrd for ServiceDescriptor {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for ServiceDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}{} {}{} {}{} {}{}",
            format!("{}", "name:".dimmed()),
            self.service_name,
            format!("{}", "cn:".dimmed()),
            self.actor_cn,
            format!("{}", "zpr_addr:".dimmed()),
            self.zpr_addr,
            format!("{}", "dock_zpr_addr:".dimmed()),
            self.dock_zpr_addr,
        )
    }
}

#[derive(Debug, Serialize, Deserialize, Eq)]
#[allow(dead_code)]
pub struct HostRecordBrief {
    pub ctime: i64, // unix SECONDS (not millis)
    pub cn: String,
    pub zpr_addr: String,
    pub ident: String,
    pub node: bool,
}

impl PartialEq for HostRecordBrief {
    fn eq(&self, other: &Self) -> bool {
        self.cn == other.cn
    }
}

impl Ord for HostRecordBrief {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.cn.cmp(&other.cn)
    }
}

impl PartialOrd for HostRecordBrief {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for HostRecordBrief {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ts: DateTime<Utc> = DateTime::from_timestamp(self.ctime, 0).unwrap();
        write!(
            f,
            "{} {}{}{} @ {} {}",
            self.cn,
            "(created: ".dimmed(),
            ts.to_rfc3339_opts(SecondsFormat::Secs, true).cyan(),
            ")".dimmed(),
            self.zpr_addr.yellow(),
            if self.node {
                "[node]".green()
            } else {
                "".normal()
            },
        )
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeRecordBrief {
    pub pending: u32,
    pub last_contact: Option<i64>, // unix SECONDS
    pub visa_requests: u64,
    pub connect_requests: u64,
    pub in_sync: bool,
    pub approved_vreqs: u64,
    pub denied_vreqs: u64,
    pub last_vreq: Option<i64>, // unix SECONDS
    pub adapters: Vec<String>,
    pub links: Vec<String>,
    pub visas: Vec<u64>,
    pub visas_enqueued: Vec<u64>,
    pub revocations_enqueued_count: u64,
    pub vss_port: Option<u16>,
}

impl fmt::Display for NodeRecordBrief {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let last_contact = match self.last_contact {
            Some(lc) => Some(DateTime::from_timestamp(lc, 0).unwrap()),
            None => None,
        };
        let last_request = match self.last_vreq {
            Some(lr) => Some(DateTime::from_timestamp(lr, 0).unwrap()),
            None => None,
        };

        write!(
            f,
            "{} {} {} {} {} {} {} {}",
            format!("{}{}", "pending:".dimmed(), self.pending),
            format!(
                "{}{}",
                "SYNC:".dimmed(),
                if self.in_sync {
                    "YES".green()
                } else {
                    "NO".red()
                }
            ),
            format!(
                "{} {}",
                "last_contact:".dimmed(),
                match last_contact {
                    Some(lc) => lc.to_rfc3339_opts(SecondsFormat::Secs, true).cyan(),
                    None => "never".to_string().red(),
                }
            ),
            // '[vreqs: VAL' (vreqs_appr: VAL | vreqs_den: VAL) | vinstalled: [VAL, VAL, VAL] | venqueued: [VAL, VAL]]'
            format!(
                "{} {} {} {} {}",
                format!(
                    "{}{} {}{} {} {}{}{}",
                    "[vreqs:".dimmed(),
                    self.visa_requests,
                    "(vreqs_appr".dimmed(),
                    self.approved_vreqs,
                    "|".dimmed(),
                    "vreqs_den".dimmed(),
                    self.denied_vreqs,
                    ")"
                ),
                "|".dimmed(),
                format!("{}{:?}", "vinstalled:".dimmed(), self.visas,),
                "|".dimmed(),
                format!(
                    "{}{:?}{}",
                    "venqueued:".dimmed(),
                    self.visas_enqueued,
                    "]".dimmed()
                ),
            ),
            format!(
                "{} {}",
                "last_request:".dimmed(),
                match last_request {
                    Some(lr) => lr.to_rfc3339_opts(SecondsFormat::Secs, true).cyan(),
                    None => "never".to_string().red(),
                }
            ),
            // [creqs: VAL | adapters: [VAL, VAL, VAL] | nodes: [VAL, VAL]]
            format!(
                "{} {} {} {} {}",
                format!("{}{}", "creqs:".dimmed(), self.connect_requests,),
                "|".dimmed(),
                format!("{}{:?}", "[adapters:".dimmed(), self.adapters),
                "|".dimmed(),
                format!("{}{:?}{}", "nodes:".dimmed(), self.links, "]".dimmed()),
            ),
            format!(
                "{}{}",
                "revocations_enqueued:".dimmed(),
                self.revocations_enqueued_count
            ),
            format!(
                "{}{}",
                "vss_port:".dimmed(),
                match self.vss_port {
                    Some(port) => port.to_string(),
                    None => "no vss".to_string(),
                }
            ),
        )
    }
}

#[derive(Debug, Deserialize, Eq)]
#[allow(dead_code)]
pub struct ServiceRecord {
    pub ctime: i64, // unix SECONDS (not millis)
    pub cn: String,
    pub zpr_addr: String,
    pub ident: String,
    pub node: bool,
    pub services: Vec<String>,
}

impl fmt::Display for ServiceRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for svc in &self.services {
            write!(
                f,
                "{:<36}  {}  @ {} {}\n",
                svc,
                self.cn.cyan(),
                self.zpr_addr.yellow(),
                if self.node {
                    "[node]".green()
                } else {
                    "".normal()
                },
            )?;
        }
        Ok(())
    }
}

impl PartialEq for ServiceRecord {
    fn eq(&self, other: &Self) -> bool {
        self.cn == other.cn
    }
}

impl Ord for ServiceRecord {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.cn.cmp(&other.cn)
    }
}

impl PartialOrd for ServiceRecord {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Serialize, Deserialize)]
pub struct AuthRevokeDescriptor {
    pub ty: String,
    pub cn: String,
}

impl fmt::Display for AuthRevokeDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            format!("{}", "type".dimmed()),
            self.ty,
            format!("{}", "cn".dimmed()),
            self.cn
        )
    }
}

// Not exactly an api type, but the version generated by the compiler has some parts
// to it separated by colons.  This splits them up and makes it possible to pretty
// print.
#[allow(dead_code)]
pub struct PolicyVersion {
    parts: Vec<String>,
}

#[allow(dead_code)]
impl PolicyVersion {
    pub fn new(version: &str) -> Self {
        PolicyVersion {
            parts: version.split(':').map(|s| s.to_string()).collect(),
        }
    }
}

impl fmt::Display for PolicyVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let colors = [Color::Cyan, Color::Green, Color::Blue, Color::BrightBlue];
        for (i, part) in self.parts.iter().enumerate() {
            if i > 0 {
                write!(f, "{}", ":".bold())?;
            }
            write!(f, "{}", part.color(colors[i % 4]))?;
        }
        Ok(())
    }
}

#[allow(dead_code)]
pub fn reason_for(sc: StatusCode) -> String {
    match sc.canonical_reason() {
        Some(reason) => reason.to_string(),
        None => "unknown".to_string(),
    }
}

/// Simple struct with a "cn" field.
#[derive(Serialize, Deserialize, Debug)]
pub struct CnEntry {
    pub cn: String,
}

impl fmt::Display for CnEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", format!("{}", "cn".dimmed()), self.cn)
    }
}
