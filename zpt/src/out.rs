use std::collections::HashMap;

use chrono::{DateTime, Local, SecondsFormat};
use colored::Colorize;

use libeval::actor::Actor;
use libeval::eval::{EvalError, Hit, VisaProps};

/// OutFmt for controlling how ZPT emits output text.
#[derive(Clone, Copy, Debug)]
pub enum OutFmt {
    /// Produces human-readable output with fun colors.
    Human,

    /// Produces JSONL output suitable for machine parsing.
    Json,
}

/// The OutputFormatter defines a bunch of very specific output functions
/// tied to the running of ZPT.
pub trait OutputFormatter {
    /// Print an error message
    fn write_error(&self, msg: &str);

    /// Echo an input line (from file or stdin) on the output. NOP for json.
    fn write_echo_line(&self, line: &str);

    /// Write an ALLOW eval decision with details.
    fn write_allow(
        &self,
        instr_num: usize,
        hits: &[Hit],
        vprop_results: &[Result<VisaProps, EvalError>],
    );

    /// Write a DENY eval decision with details.
    fn write_deny(&self, instr_num: usize, hits: &[Hit]);

    /// Write a NO MATCH eval decision with details.
    fn write_no_match(&self, instr_num: usize, reason: &str);

    /// Write the current actor database.
    fn write_actor_db(&self, db: &HashMap<String, Actor>);
}

impl OutputFormatter for OutFmt {
    fn write_error(&self, msg: &str) {
        match self {
            OutFmt::Human => human::write_error(msg),
            OutFmt::Json => json::write_error(msg),
        }
    }

    fn write_echo_line(&self, line: &str) {
        match self {
            OutFmt::Human => human::write_echo_line(line),
            OutFmt::Json => json::write_echo_line(line),
        }
    }

    fn write_allow(
        &self,
        instr_num: usize,
        hits: &[Hit],
        vprop_results: &[Result<VisaProps, EvalError>],
    ) {
        match self {
            OutFmt::Human => human::write_allow(instr_num, hits, vprop_results),
            OutFmt::Json => json::write_allow(instr_num, hits, vprop_results),
        }
    }

    fn write_deny(&self, instr_num: usize, hits: &[Hit]) {
        match self {
            OutFmt::Human => human::write_deny(instr_num, hits),
            OutFmt::Json => json::write_deny(instr_num, hits),
        }
    }

    fn write_no_match(&self, instr_num: usize, reason: &str) {
        match self {
            OutFmt::Human => human::write_no_match(instr_num, reason),
            OutFmt::Json => json::write_no_match(instr_num, reason),
        }
    }

    fn write_actor_db(&self, db: &HashMap<String, Actor>) {
        match self {
            OutFmt::Human => human::write_actor_db(db),
            OutFmt::Json => json::write_actor_db(db),
        }
    }
}

mod human {
    use super::*;

    pub fn write_error(msg: &str) {
        eprintln!("{}: {msg}", "Error".red());
    }

    pub fn write_echo_line(line: &str) {
        println!(">  {}", line.dimmed());
    }

    pub fn write_allow(
        instr_num: usize,
        hits: &[Hit],
        vprop_results: &[Result<VisaProps, EvalError>],
    ) {
        println!(
            "{}: {}",
            format!("eval {}", instr_num).yellow(),
            "Decision ALLOW".green()
        );
        for (hitnum, hit) in hits.iter().enumerate() {
            print!(
                "{}",
                format!(
                    "  [hit {}]  Matched rule: #{} direction: {}",
                    hitnum, hit.match_idx, hit.direction
                )
                .cyan()
            );
            if let Some(ref sig) = hit.signal {
                println!("      Signal: '{}' to {}", sig.message, sig.service);
            } else {
                println!();
            }
            match &vprop_results[hitnum] {
                Err(e) => println!("ERROR requesting visa: {}", e),
                Ok(props) => {
                    println!("     {}   {}", "zpl".dimmed(), props.get_zpl().magenta());
                    println!("    {}   {props}", "visa".dimmed());
                }
            }
        }
    }

    pub fn write_deny(instr_num: usize, _hits: &[Hit]) {
        // TODO: Show more info about the DENY
        println!(
            "{}: {}",
            format!("eval {}", instr_num).yellow(),
            "Decision DENY".red()
        );
    }

    pub fn write_no_match(instr_num: usize, reason: &str) {
        println!(
            "{}: {} - {}",
            format!("eval {}", instr_num).yellow(),
            "Decision NO MATCH".red(),
            reason.cyan()
        );
    }

    pub fn write_actor_db(db: &HashMap<String, Actor>) {
        println!("Actor database:");
        if db.is_empty() {
            println!("  (empty)");
            return;
        }
        for (name, actor) in db {
            println!("  [{}]", name);
            for attr in actor.attrs_iter() {
                let dt: DateTime<Local> = attr.get_expires().into();
                println!(
                    "     {}:{} (exp {})",
                    attr.get_key(),
                    attr.get_value(),
                    dt.to_rfc3339_opts(SecondsFormat::Secs, false)
                );
            }
        }
    }
}

mod json {

    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    enum Decision {
        Allow,
        Deny,
        NoMatch,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    enum MsgType {
        Error,
        Eval,
        DumpDb,
    }

    #[derive(Serialize)]
    struct JError {
        kind: MsgType,
        error: String,
    }

    #[derive(Serialize)]
    struct JDeny<'a> {
        kind: MsgType,
        instruction: usize,
        decision: Decision,
        hit: &'a Hit,
    }

    #[derive(Serialize)]
    #[serde(tag = "visa_status", rename_all = "snake_case")]
    enum VisaOutcome<'a> {
        Success(&'a VisaProps),
        Error(String),
    }

    #[derive(Serialize)]
    struct JAllow<'a> {
        kind: MsgType,
        instruction: usize,
        decision: Decision,
        hit: &'a Hit,
        visa: VisaOutcome<'a>,
    }

    #[derive(Serialize)]
    struct JNoMatch {
        kind: MsgType,
        instruction: usize,
        decision: Decision,
        reason: String,
    }

    #[derive(Serialize)]
    struct JActorDB<'a> {
        kind: MsgType,
        actors: &'a HashMap<String, Actor>,
    }

    pub fn write_error(msg: &str) {
        let e = JError {
            kind: MsgType::Error,
            error: msg.to_string(),
        };
        let _ = serde_json::to_writer(std::io::stderr(), &e);
        eprintln!();
    }

    pub fn write_echo_line(_line: &str) {} // NOP

    pub fn write_allow(
        instr_num: usize,
        hits: &[Hit],
        vprop_results: &[Result<VisaProps, EvalError>],
    ) {
        for (i, hit) in hits.iter().enumerate() {
            let voutcome = match vprop_results.get(i) {
                Some(Ok(vp)) => VisaOutcome::Success(vp),
                Some(Err(e)) => VisaOutcome::Error(e.to_string()),
                None => VisaOutcome::Error("Internal error: missing visa outcome".to_string()),
            };
            let a = JAllow {
                kind: MsgType::Eval,
                instruction: instr_num,
                decision: Decision::Allow,
                hit: hit,
                visa: voutcome,
            };
            let _ = serde_json::to_writer(std::io::stdout(), &a);
            println!();
        }
    }

    pub fn write_deny(instr_num: usize, hits: &[Hit]) {
        for hit in hits {
            let d = JDeny {
                kind: MsgType::Eval,
                instruction: instr_num,
                decision: Decision::Deny,
                hit: hit,
            };
            let _ = serde_json::to_writer(std::io::stdout(), &d);
            println!();
        }
    }

    pub fn write_no_match(instr_num: usize, reason: &str) {
        let nm = JNoMatch {
            kind: MsgType::Eval,
            instruction: instr_num,
            decision: Decision::NoMatch,
            reason: reason.to_string(),
        };
        let _ = serde_json::to_writer(std::io::stdout(), &nm);
        println!();
    }

    pub fn write_actor_db(b: &HashMap<String, Actor>) {
        let adb = JActorDB {
            kind: MsgType::DumpDb,
            actors: b,
        };
        let _ = serde_json::to_writer(std::io::stdout(), &adb);
        println!();
    }
}
