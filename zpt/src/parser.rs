use libeval::actor::Actor;
use libeval::packet;
use std::path::PathBuf;
use std::time::Duration;

use crate::error::ParseError;
use crate::zmachine::{ActorExpr, InstrExtra, Instruction};

pub fn parse(input_line: &str) -> Result<Instruction, ParseError> {
    let mut parsing = Parsing::new(input_line);
    match parsing.pop_word()?.to_lowercase().as_str() {
        "help" => Ok(Instruction::Help),
        "dumpdb" => Ok(Instruction::Dumpdb),
        "load" => {
            let path = parsing.pop_path()?;
            Ok(Instruction::Load(path))
        }
        "set" => {
            // TODO: Expiration
            let actor_name = parsing.pop_word()?;
            let attr_expr = parsing.pop_eol()?;
            let (key, val) = parse_key_value(attr_expr)?;
            Ok(Instruction::Set {
                name: actor_name,
                key,
                value: val,
            })
        }
        "eval" => {
            let prot_str = parsing.pop_word()?.to_lowercase();
            match prot_str.as_str() {
                "tcp" => Ok(parse_tcp_expr(parsing.pop_eol()?)?),
                "udp" => Err(ParseError::UnknownInstruction),
                "icmp6" => Err(ParseError::UnknownInstruction),
                _ => Err(ParseError::UnknownInstruction),
            }
        }
        _ => Err(ParseError::UnknownInstruction),
    }
}

fn parse_key_value(expr: String) -> Result<(String, String), ParseError> {
    let expr = expr.trim();
    if expr.is_empty() {
        return Err(ParseError::InvalidFormat(
            "empty attribute expression".to_string(),
        ));
    }
    if expr.starts_with('#') {
        // Tag
        let tag = expr[1..].trim();
        if tag.is_empty() {
            return Err(ParseError::InvalidFormat(
                "empty tag in attribute expression".to_string(),
            ));
        }
        Ok(("zpr.tag".to_string(), tag.to_string()))
    } else if let Some(colon_pos) = expr.find(':') {
        let key = expr[..colon_pos].trim();
        let value = expr[colon_pos + 1..].trim();
        if key.is_empty() {
            return Err(ParseError::InvalidFormat(
                "empty key in attribute expression".to_string(),
            ));
        }
        if value.starts_with('{') && value.ends_with('}') {
            // Multi-value
            let inner = &value[1..value.len() - 1];
            let values: Vec<String> = inner
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if values.is_empty() {
                return Err(ParseError::InvalidFormat(
                    "empty multi-value attribute expression".to_string(),
                ));
            }
            Ok((key.to_string(), values.join(", ")))
        } else {
            // Single value (can be empty)
            Ok((key.to_string(), value.to_string()))
        }
    } else {
        Err(ParseError::InvalidFormat(
            "attribute expression must contain ':' or start with '#'".to_string(),
        ))
    }
}

// format is:
//   `tcp <src_actor_name>.<src_port> > <dst_actor_name>.<dst_port> <flags>`
//
// Where <flags> is in tcp-dump format, e.g.:
//    [] no flags (or flags is just not there)
//    [S] syn
//    [P] push
//    [R] reset
//    [F] fin
// Adding a '.' means ACK, so for example:
//    [S.] is syn-ack
//    [P.] is push-ack
//    [.] is ack without other flags
//
fn parse_tcp_expr(expr: String) -> Result<Instruction, ParseError> {
    let expr = expr.trim();
    if expr.is_empty() {
        return Err(ParseError::InvalidFormat(
            "empty tcp expression".to_string(),
        ));
    }
    let mut parts = expr.split_whitespace();
    let src_part = parts
        .next()
        .ok_or_else(|| ParseError::InvalidFormat("missing source in tcp expression".to_string()))?;
    let arrow = parts
        .next()
        .ok_or_else(|| ParseError::InvalidFormat("missing '>' in tcp expression".to_string()))?;
    if arrow != ">" {
        return Err(ParseError::InvalidFormat(
            "expected '>' in tcp expression".to_string(),
        ));
    }
    let dst_part = parts.next().ok_or_else(|| {
        ParseError::InvalidFormat("missing destination in tcp expression".to_string())
    })?;
    let flags_part = parts.next(); // optional

    // Parse source
    let (src_actor, src_port) = parse_actor_port(src_part)?;
    let source_expr = match src_port {
        Some(port) => ActorExpr::ActorNameAndPort(src_actor, port),
        None => ActorExpr::ActorName(src_actor),
    };
    // Parse destination
    let (dst_actor, dst_port) = parse_actor_port(dst_part)?;
    let dest_expr = match dst_port {
        Some(port) => ActorExpr::ActorNameAndPort(dst_actor, port),
        None => ActorExpr::ActorName(dst_actor),
    };

    // Parse flags
    let mut flag_byte = 0u8;

    if let Some(flags_str) = flags_part {
        let flags_str = flags_str.trim();
        if !flags_str.starts_with('[') || !flags_str.ends_with(']') {
            return Err(ParseError::InvalidFormat(
                "flags must be enclosed in []".to_string(),
            ));
        }
        let flags_inner = &flags_str[1..flags_str.len() - 1];
        for ch in flags_inner.chars() {
            match ch {
                'F' => flag_byte |= packet::tcp::FIN,
                'S' => flag_byte |= packet::tcp::SYN,
                'R' => flag_byte |= packet::tcp::RST,
                'P' => flag_byte |= packet::tcp::PSH,
                '.' => flag_byte |= packet::tcp::ACK,
                _ => {
                    return Err(ParseError::InvalidFormat(format!(
                        "unknown TCP flag '{}'",
                        ch
                    )));
                }
            }
        }
    }
    let flags = if flag_byte > 0 {
        Some(InstrExtra::TcpFlags(flag_byte))
    } else {
        None
    };

    Ok(Instruction::Eval {
        prot: packet::ip_proto::TCP,
        source_expr,
        dest_expr,
        extra: flags,
    })
}

// Actor name is required, port is optional.
fn parse_actor_port(actor_and_maybe_port: &str) -> Result<(String, Option<u16>), ParseError> {
    let (actor, port) = if let Some(dot_pos) = actor_and_maybe_port.rfind('.') {
        let actor = actor_and_maybe_port[..dot_pos].trim().to_string();
        let port_str = actor_and_maybe_port[dot_pos + 1..].trim();
        if port_str.is_empty() {
            return Err(ParseError::InvalidFormat(
                "empty port in actor.port expression".to_string(),
            ));
        }
        let port: u16 = port_str.parse().map_err(|_| {
            ParseError::InvalidFormat(format!("invalid port number '{}'", port_str))
        })?;
        (actor, Some(port))
    } else {
        // Just actor
        (actor_and_maybe_port.trim().to_string(), None)
    };

    if actor.is_empty() {
        return Err(ParseError::InvalidFormat(
            "empty actor name in actor.port expression".to_string(),
        ));
    }
    Ok((actor, port))
}

/// A sort of cursor style parser.
struct Parsing {
    input: String,
    cpos: usize, // input[cpos] is next position to start parsing.
}

impl Parsing {
    fn new<S: Into<String>>(input_line: S) -> Self {
        Parsing {
            input: input_line.into(),
            cpos: 0,
        }
    }

    fn pop_word(&mut self) -> Result<String, ParseError> {
        let word = self.read_to(' ', true)?;
        Ok(word)
    }

    fn pop_eol(&mut self) -> Result<String, ParseError> {
        if self.cpos >= self.input.len() {
            return Err(ParseError::UnexpectedEof);
        }
        let word = String::from(self.input[self.cpos..].trim());
        self.cpos = self.input.len();
        Ok(word)
    }

    fn pop_path(&mut self) -> Result<PathBuf, ParseError> {
        let word = self.pop_word()?;
        Ok(PathBuf::from(word))
    }

    fn read_to(&mut self, delim: char, or_eol: bool) -> Result<String, ParseError> {
        if self.cpos >= self.input.len() {
            return Err(ParseError::UnexpectedEof);
        }
        let rest = &self.input[self.cpos..];
        if let Some(pos) = rest.find(delim) {
            let word = &rest[..pos];
            self.cpos += pos + 1; // +1 to skip the delimiter
            Ok(word.to_string())
        } else if or_eol {
            // No delimiter found: return rest.
            let word = rest;
            self.cpos = self.input.len();
            Ok(word.to_string())
        } else {
            Err(ParseError::UnexpectedEof)
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_parses_load() {
        let ins = parse("load /path/to/policy.zpr").unwrap();
        match ins {
            Instruction::Load(path) => {
                assert_eq!(path.to_string_lossy(), "/path/to/policy.zpr");
            }
            _ => panic!("expected Load instruction"),
        }
    }

    #[test]
    fn test_parses_simple_set() {
        let ins = parse("set alice color:red").unwrap();
        match ins {
            Instruction::Set { name, key, value } => {
                assert_eq!(name, "alice");
                assert_eq!(key, "color");
                assert_eq!(value, "red");
            }
            _ => panic!("expected Set instruction"),
        }
    }

    #[test]
    fn test_parses_simple_empty() {
        let ins = parse("set alice color:").unwrap();
        match ins {
            Instruction::Set { name, key, value } => {
                assert_eq!(name, "alice");
                assert_eq!(key, "color");
                assert_eq!(value, "");
            }
            _ => panic!("expected Set instruction"),
        }
    }

    #[test]
    fn test_parses_simple_set_tag() {
        let ins = parse("set alice #red").unwrap();
        match ins {
            Instruction::Set { name, key, value } => {
                assert_eq!(name, "alice");
                assert_eq!(key, "zpr.tag");
                assert_eq!(value, "red");
            }
            _ => panic!("expected Set instruction"),
        }
    }

    #[test]
    fn test_parses_simple_set_multi() {
        let ins = parse("set alice colors:{red, blue}").unwrap();
        match ins {
            Instruction::Set { name, key, value } => {
                assert_eq!(name, "alice");
                assert_eq!(key, "colors");
                assert_eq!(value, "red, blue");
            }
            _ => panic!("expected Set instruction"),
        }
    }

    #[test]
    fn test_parse_tcp_expr() {
        let ins = parse("tcp alice.1234 > bob.80 [S.]").unwrap();
        match ins {
            Instruction::Eval {
                prot,
                source_expr,
                dest_expr,
                extra,
            } => {
                assert_eq!(prot, packet::ip_proto::TCP);
                match source_expr {
                    ActorExpr::ActorNameAndPort(name, port) => {
                        assert_eq!(name, "alice");
                        assert_eq!(port, 1234);
                    }
                    _ => panic!("expected ActorNameAndPort for source"),
                }
                match dest_expr {
                    ActorExpr::ActorNameAndPort(name, port) => {
                        assert_eq!(name, "bob");
                        assert_eq!(port, 80);
                    }
                    _ => panic!("expected ActorNameAndPort for dest"),
                }
                match extra {
                    Some(InstrExtra::TcpFlags(flags)) => {
                        assert_eq!(flags, packet::tcp::SYN | packet::tcp::ACK);
                    }
                    _ => panic!("expected TcpFlags extra"),
                }
            }
            _ => panic!("expected Eval instruction"),
        }
    }

    #[test]
    fn test_parse_tcp_expr_no_flags() {
        for input_line in [
            "tcp alice.1234 > bob.80",
            "tcp alice.1234 > bob.80 []",
            "tcp alice.1234 > bob.80    ",
        ] {
            let ins = parse(input_line).unwrap();
            match ins {
                Instruction::Eval {
                    prot,
                    source_expr,
                    dest_expr,
                    extra,
                } => {
                    assert_eq!(prot, packet::ip_proto::TCP);
                    match source_expr {
                        ActorExpr::ActorNameAndPort(name, port) => {
                            assert_eq!(name, "alice");
                            assert_eq!(port, 1234);
                        }
                        _ => panic!("expected ActorNameAndPort for source"),
                    }
                    match dest_expr {
                        ActorExpr::ActorNameAndPort(name, port) => {
                            assert_eq!(name, "bob");
                            assert_eq!(port, 80);
                        }
                        _ => panic!("expected ActorNameAndPort for dest"),
                    }
                    match extra {
                        None => {}
                        _ => panic!("expected no extra"),
                    }
                }
                _ => panic!("expected Eval instruction"),
            }
        }
    }
}
