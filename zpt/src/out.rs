use std::collections::HashMap;
use std::io::Write;

use chrono::{DateTime, Local, SecondsFormat};
use colored::Colorize;

use libeval::actor::Actor;
use libeval::eval::{EvalError, Hit, VisaProps};

/// The OutputFormatter defines a bunch of very specific output functions
/// tied to the running of ZPT.
pub trait OutputFormatter {
    /// Print an error message
    fn write_error(&mut self, msg: &str);

    /// Echo an input line (from file or stdin) on the output. NOP for json.
    fn write_echo_line(&mut self, line: &str);

    /// Write an ALLOW eval decision with details.
    fn write_allow(
        &mut self,
        instr_num: usize,
        hits: &[Hit],
        vprop_results: &[Result<VisaProps, EvalError>],
    );

    /// Write a DENY eval decision with details.
    fn write_deny(&mut self, instr_num: usize, hits: &[Hit]);

    /// Write a NO MATCH eval decision with details.
    fn write_no_match(&mut self, instr_num: usize, reason: &str);

    /// Write the current actor database.
    fn write_actor_db(&mut self, db: &HashMap<String, Actor>);
}

pub struct JsonFormatter<WOut: Write> {
    out: WOut,
}

pub struct HumanFormatter<WOut: Write> {
    out: WOut,
}

impl<WOut: Write> HumanFormatter<WOut> {
    /// Create new human formatter that writes to the given writer.
    pub fn new(out: WOut) -> Self {
        HumanFormatter { out }
    }
}

impl<WOut: Write> JsonFormatter<WOut> {
    /// Create a new JSON formatter that writes to the given writer.
    pub fn new(out: WOut) -> Self {
        JsonFormatter { out }
    }
}

impl<WOut: Write> OutputFormatter for HumanFormatter<WOut> {
    fn write_error(&mut self, msg: &str) {
        let _ = writeln!(self.out, "{}: {msg}", "Error".red());
    }

    fn write_echo_line(&mut self, line: &str) {
        let _ = writeln!(self.out, ">  {}", line.dimmed());
    }

    fn write_allow(
        &mut self,
        instr_num: usize,
        hits: &[Hit],
        vprop_results: &[Result<VisaProps, EvalError>],
    ) {
        let _ = writeln!(
            self.out,
            "{}: {}",
            format!("eval {}", instr_num).yellow(),
            "Decision ALLOW".green()
        );

        for (hitnum, hit) in hits.iter().enumerate() {
            let _ = self.write_hit(hitnum, hit);
            match vprop_results.get(hitnum) {
                Some(Ok(props)) => {
                    let _ = writeln!(self.out, "    {}   {props}", "visa".dimmed());
                    let _ = writeln!(
                        self.out,
                        "     {}   {}",
                        "zpl".dimmed(),
                        props.get_zpl().magenta()
                    );
                }
                Some(Err(e)) => {
                    let _ = writeln!(self.out, "ERROR requesting visa: {}", e);
                }
                None => {
                    let _ = writeln!(
                        self.out,
                        "ERROR: No visa properties found for hit {}",
                        hitnum
                    );
                }
            }
        }
    }

    fn write_deny(&mut self, instr_num: usize, hits: &[Hit]) {
        // TODO: Show the zpl with the deny?
        let _ = writeln!(
            self.out,
            "{}: {}",
            format!("eval {}", instr_num).yellow(),
            "Decision DENY".red()
        );
        for (hitnum, hit) in hits.iter().enumerate() {
            let _ = self.write_hit(hitnum, hit);
        }
    }

    fn write_no_match(&mut self, instr_num: usize, reason: &str) {
        let _ = writeln!(
            self.out,
            "{}: {} - {}",
            format!("eval {}", instr_num).yellow(),
            "Decision NO MATCH".red(),
            reason.cyan()
        );
    }

    fn write_actor_db(&mut self, db: &HashMap<String, Actor>) {
        let _ = writeln!(self.out, "Actor database:");
        if db.is_empty() {
            let _ = writeln!(self.out, "  (empty)");
            return;
        }
        for (name, actor) in db {
            let _ = writeln!(self.out, "  [{}]", name);
            for attr in actor.attrs_iter() {
                let dt: DateTime<Local> = attr.get_expires().into();
                let _ = writeln!(
                    self.out,
                    "     {}:{} (exp {})",
                    attr.get_key(),
                    attr.get_value(),
                    dt.to_rfc3339_opts(SecondsFormat::Secs, false)
                );
            }
        }
    }
}

impl<WOut: Write> HumanFormatter<WOut> {
    fn write_hit(&mut self, idx: usize, hit: &Hit) -> std::io::Result<()> {
        writeln!(
            self.out,
            "{}",
            format!(
                "  [hit {}]  Matched rule: #{} direction: {}",
                idx, hit.match_idx, hit.direction
            )
            .cyan()
        )?;
        if let Some(ref sig) = hit.signal {
            writeln!(
                self.out,
                "  {}   {} -> {}",
                "signal".dimmed(),
                sig.message.blue(),
                sig.service.blue()
            )
        } else {
            Ok(())
        }
    }
}

mod json {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum Decision {
        Allow,
        Deny,
        NoMatch,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    pub enum MsgType {
        Error,
        Eval,
        DumpDb,
    }

    #[derive(Serialize)]
    pub struct JError {
        pub kind: MsgType,
        pub error: String,
    }

    #[derive(Serialize)]
    pub struct JDeny<'a> {
        pub kind: MsgType,
        pub instruction: usize,
        pub decision: Decision,
        pub hit: &'a Hit,
    }

    #[derive(Serialize)]
    #[serde(tag = "visa_status", rename_all = "snake_case")]
    pub enum VisaOutcome<'a> {
        Success(&'a VisaProps),
        Error(String),
    }

    #[derive(Serialize)]
    pub struct JAllow<'a> {
        pub kind: MsgType,
        pub instruction: usize,
        pub decision: Decision,
        pub hit: &'a Hit,
        pub visa: VisaOutcome<'a>,
    }

    #[derive(Serialize)]
    pub struct JNoMatch {
        pub kind: MsgType,
        pub instruction: usize,
        pub decision: Decision,
        pub reason: String,
    }

    #[derive(Serialize)]
    pub struct JActorDB<'a> {
        pub kind: MsgType,
        pub actors: &'a HashMap<String, Actor>,
    }
}

impl<WOut: Write> OutputFormatter for JsonFormatter<WOut> {
    fn write_error(&mut self, msg: &str) {
        let e = json::JError {
            kind: json::MsgType::Error,
            error: msg.to_string(),
        };
        let _ = serde_json::to_writer(&mut self.out, &e);
        let _ = writeln!(self.out);
    }

    fn write_echo_line(&mut self, _line: &str) {} // NOP

    fn write_allow(
        &mut self,
        instr_num: usize,
        hits: &[Hit],
        vprop_results: &[Result<VisaProps, EvalError>],
    ) {
        for (i, hit) in hits.iter().enumerate() {
            let voutcome = match vprop_results.get(i) {
                Some(Ok(vp)) => json::VisaOutcome::Success(vp),
                Some(Err(e)) => json::VisaOutcome::Error(e.to_string()),
                None => {
                    json::VisaOutcome::Error("Internal error: missing visa outcome".to_string())
                }
            };
            let a = json::JAllow {
                kind: json::MsgType::Eval,
                instruction: instr_num,
                decision: json::Decision::Allow,
                hit: hit,
                visa: voutcome,
            };
            let _ = serde_json::to_writer(&mut self.out, &a);
            let _ = writeln!(self.out);
        }
    }

    fn write_deny(&mut self, instr_num: usize, hits: &[Hit]) {
        for hit in hits {
            let d = json::JDeny {
                kind: json::MsgType::Eval,
                instruction: instr_num,
                decision: json::Decision::Deny,
                hit: hit,
            };
            let _ = serde_json::to_writer(&mut self.out, &d);
            let _ = writeln!(self.out);
        }
    }

    fn write_no_match(&mut self, instr_num: usize, reason: &str) {
        let nm = json::JNoMatch {
            kind: json::MsgType::Eval,
            instruction: instr_num,
            decision: json::Decision::NoMatch,
            reason: reason.to_string(),
        };
        let _ = serde_json::to_writer(&mut self.out, &nm);
        let _ = writeln!(self.out);
    }

    fn write_actor_db(&mut self, b: &HashMap<String, Actor>) {
        let adb = json::JActorDB {
            kind: json::MsgType::DumpDb,
            actors: b,
        };
        let _ = serde_json::to_writer(&mut self.out, &adb);
        let _ = writeln!(self.out);
    }
}
