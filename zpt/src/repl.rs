use colored::Colorize;

use std::path::Path;

use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;

use crate::error::ZptError;
use crate::out::OutputFormatter;
use crate::parser;
use crate::zmachine::{State, ZMachine};

pub struct Repl<'a> {
    machine: ZMachine,
    state: State,
    rl: rustyline::DefaultEditor,
    outfmt: &'a mut Box<dyn OutputFormatter>,
}

enum Command {
    Line(String),
    Exit,
}

impl<'a> Repl<'a> {
    pub fn new(base_path: &Path, outfmt: &'a mut Box<dyn OutputFormatter>) -> Self {
        Repl {
            machine: ZMachine::new(base_path),
            state: State::new(),
            rl: DefaultEditor::new().unwrap(),
            outfmt: outfmt,
        }
    }

    fn is_exit(&self, trimmed_input: &str) -> bool {
        trimmed_input.eq_ignore_ascii_case("exit")
            || trimmed_input.eq_ignore_ascii_case("quit")
            || trimmed_input.eq_ignore_ascii_case("q")
    }

    fn is_empty(&self, trimmed_input: &str) -> bool {
        trimmed_input.is_empty() || trimmed_input.starts_with('#')
    }

    /// Run a read-eval-print loop.
    pub fn run(&mut self) -> Result<(), ZptError> {
        let mut input;
        loop {
            match self.prompt()? {
                Command::Line(s) => input = s,
                Command::Exit => {
                    break;
                }
            }
            println!();

            let trimmed = input.trim();
            if trimmed.is_empty() {
                continue;
            }
            if self.is_exit(trimmed) {
                break;
            }
            if self.is_empty(trimmed) {
                continue;
            }
            match parser::parse(trimmed) {
                Ok(instruction) => {
                    match self
                        .machine
                        .execute(&instruction, &mut self.state, &mut self.outfmt)
                    {
                        Ok(_) => {}
                        Err(e) => self.outfmt.write_error(&e.to_string()),
                    }
                }
                Err(e) => self.outfmt.write_error(&e.to_string()),
            };
        }
        Ok(())
    }

    pub fn run_script<'s, I>(&mut self, lines_iter: I) -> Result<(), ZptError>
    where
        I: Iterator<Item = &'s str>,
    {
        for line in lines_iter {
            let trimmed = line.trim();
            if self.is_empty(trimmed) {
                continue;
            }
            self.outfmt.write_echo_line(trimmed);
            if self.is_exit(trimmed) {
                break;
            }

            let instr = parser::parse(trimmed)?;
            self.machine
                .execute(&instr, &mut self.state, &mut self.outfmt)?;
        }
        Ok(())
    }

    fn prompt(&mut self) -> Result<Command, ZptError> {
        loop {
            let readline = self.rl.readline("zpt> ");
            match readline {
                Ok(line) => {
                    let trimmed = line.trim();
                    if self.is_empty(trimmed) {
                        continue;
                    }
                    self.rl.add_history_entry(trimmed)?;
                    if self.is_exit(trimmed) {
                        return Ok(Command::Exit);
                    }
                    return Ok(Command::Line(trimmed.to_string()));
                }
                Err(ReadlineError::Interrupted) => {
                    // ^C
                    return Ok(Command::Exit);
                }
                Err(ReadlineError::Eof) => {
                    // ^D
                    return Ok(Command::Exit);
                }
                Err(err) => {
                    eprintln!("{}: {:?}", "Error".red(), err);
                    return Ok(Command::Exit);
                }
            }
        }
    }
}
