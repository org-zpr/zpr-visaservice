//! z-machine is the ZPT execution machine which executes ZPT "programs" line by
//! line.  Program lines either update state or sends API calls to the executor.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{MachineError, PioError};
use crate::pio;
use libeval::actor::Actor;
use libeval::eval::EvalContext;
use libeval::packet::{self, PacketDesc};

const DEF_SOURCE_ADDR: &str = "fd5a:5052:3000::1";
const DEF_DEST_ADDR: &str = "fd5a:5052:3000::2";

/// IP Protocol is 8 bits.
type ip_proto_t = u8;

#[derive(Debug, Clone)]
pub enum Instruction {
    Help,
    Load(PathBuf),
    Set {
        name: String,
        key: String,
        value: String,
    },
    Eval {
        prot: ip_proto_t,
        source_expr: ActorExpr,
        dest_expr: ActorExpr,
        extra: Option<InstrExtra>,
    },
    Dumpdb,
}

#[derive(Debug, Clone)]
pub enum ActorExpr {
    ActorName(String),
    ActorNameAndPort(String, u16),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InstrExtra {
    TcpFlags(u8),
    IcmpType(u8),
}

#[derive(Default)]
pub struct State {
    ctx: Option<EvalContext>,
    policy_path: Option<PathBuf>,
    actor_db: HashMap<String, Actor>,
}

pub struct ZMachine {}

enum PortRequirement {
    ErrorIfMissing(String),  // error with a message
    ErrorIfProvided(String), // error with a message
    HighPortIfMissing,       // pick a random high (>1024) port
    DefaultIfMissing(u16),   // pick a specific default port
}

impl ZMachine {
    pub fn new() -> Self {
        ZMachine {}
    }

    pub fn execute(&mut self, ins: &Instruction, state: &mut State) -> Result<(), MachineError> {
        match ins {
            Instruction::Load(path) => {
                state.load_policy(path)?;
                Ok(())
            }
            Instruction::Set { name, key, value } => {
                state.set_actor_attribute(name, key, value)?;
                Ok(())
            }
            Instruction::Eval {
                prot,
                source_expr,
                dest_expr,
                extra,
            } => {
                // Evaluate the protocol action from source to destination.
                // This may involve sending packets or simulating network actions.
                // Handle errors related to invalid expressions or unsupported protocols.
                if state.ctx.is_none() {
                    return Err(MachineError::ExecutionError(
                        "No policy loaded. Use 'load <path>' to load a policy.".to_string(),
                    ));
                }
                match *prot {
                    packet::ip_proto::TCP => self.eval_tcp(state, source_expr, dest_expr, *extra),
                    packet::ip_proto::UDP => self.eval_udp(state, source_expr, dest_expr),
                    packet::ip_proto::IPV6_ICMP => {
                        self.eval_icmp(state, source_expr, dest_expr, *extra)
                    }
                    _ => {
                        return Err(MachineError::ExecutionError(format!(
                            "Unsupported protocol: {}",
                            prot
                        )));
                    }
                }
            }
            Instruction::Dumpdb => {
                state.dump_db();
                Ok(())
            }
            Instruction::Help => {
                self.print_help();
                Ok(())
            }
        }
    }

    fn print_help(&self) {
        println!("Policy commands:");
        println!("  load <path>          - Load a ZPR policy from the specified file path.");
        println!();
        println!("Actor commands:");
        println!("  set <actor> <k>:<v>  - Set attribute <k> to value <v> for actor <actor>.");
        println!("  dumpdb               - Dump the current actor database.");
        println!();
        println!("Eval commands:");
        println!("  eval TCP <src_actor>.<src_port> > <dst_actor>.<dst_port> [flags]");
        println!("  eval UDP <src_actor> > <dst_actor>");
        println!("  eval ICMP <src_actor> > <dst_actor> [type]");
        println!();
        println!("Miscellaneous commands:");
        println!("  help                - Show this help message.");
        println!("  exit, quit, q, ^C   - Exit the REPL.");
        println!();
    }

    fn eval_tcp(
        &self,
        state: &mut State,
        source_expr: &ActorExpr,
        dest_expr: &ActorExpr,
        extra: Option<InstrExtra>,
    ) -> Result<(), MachineError> {
        let (src_actor, src_port) = self.resolve_actor(state, source_expr)?;
        let src_port = match src_port {
            Some(p) => p,
            None => 31337, // TODO: pick a random high number port
        };
        let (dst_actor, dst_port) = self.resolve_actor(state, dest_expr)?;
        let dst_port = match dst_port {
            Some(p) => p,
            None => {
                return Err(MachineError::ExecutionError(
                    "destination port required for TCP".to_string(),
                ));
            }
        };

        // TODO: Someting interesting with TCP flags?

        let pd = PacketDesc::new_tcp_req(DEF_SOURCE_ADDR, DEF_DEST_ADDR, src_port, dst_port);

        if let Some(ctx) = state.ctx.as_ref() {
            match ctx.eval_request(src_actor, dst_actor, &pd) {
                Ok(decision) => {
                    println!("decision: {:?}", decision);
                }
                Err(e) => {
                    return Err(MachineError::ExecutionError(format!(
                        "policy evaluation error: {}",
                        e
                    )));
                }
            }
        } else {
            return Err(MachineError::ExecutionError(
                "No policy loaded. Use 'load <path>' to load a policy.".to_string(),
            ));
        }
        Ok(())
    }

    fn resolve_actor<'a>(
        &self,
        state: &'a State,
        expr: &ActorExpr,
    ) -> Result<(&'a Actor, Option<u16>), MachineError> {
        let (actor, port) = match expr {
            ActorExpr::ActorName(name) => (
                state.get_actor(name).ok_or_else(|| {
                    MachineError::ExecutionError(format!("unknown actor: {name}"))
                })?,
                None,
            ),

            ActorExpr::ActorNameAndPort(name, pnum) => (
                state.get_actor(name).ok_or_else(|| {
                    MachineError::ExecutionError(format!("unknown actor: {name}"))
                })?,
                Some(*pnum),
            ),
        };
        Ok((actor, port))
    }

    fn eval_udp(
        &self,
        state: &mut State,
        source_expr: &ActorExpr,
        dest_expr: &ActorExpr,
    ) -> Result<(), MachineError> {
        Err(MachineError::ExecutionError(
            "UDP not yet implemented".to_string(),
        ))
    }

    fn eval_icmp(
        &self,
        state: &mut State,
        source_expr: &ActorExpr,
        dest_expr: &ActorExpr,
        extra: Option<InstrExtra>,
    ) -> Result<(), MachineError> {
        Err(MachineError::ExecutionError(
            "ICMP not yet implemented".to_string(),
        ))
    }
}

impl State {
    pub fn new() -> Self {
        State::default()
    }

    pub fn dump_db(&self) {
        println!("Actor database:");
        for (name, actor) in &self.actor_db {
            println!("  [{}]", name);
            for (i, attr) in actor.attrs_iter().enumerate() {
                println!("     {:?}", attr); // TODO: Add a display func to Attribute.
            }
        }
    }

    pub fn load_policy(&mut self, path: &Path) -> Result<(), PioError> {
        let policy = pio::load_policy(path)?;
        self.ctx = Some(EvalContext::new(policy));
        self.policy_path = Some(path.to_path_buf());
        // todo: centralized way to report status, eg "loaded XYZ"
        Ok(())
    }

    pub fn set_actor_attribute(
        &mut self,
        actor_name: &str,
        key: &str,
        value: &str,
    ) -> Result<(), MachineError> {
        let actor = self
            .actor_db
            .entry(actor_name.to_string())
            .or_insert_with(|| Actor::new());

        // TODO: Attribute allows duplicate attribute keys -- it should not.

        actor.add_attr(key, value, Duration::from_secs(3600)); // TODO: Expiration
        Ok(())
    }

    pub fn get_actor(&self, name: &str) -> Option<&Actor> {
        self.actor_db.get(name)
    }
}
