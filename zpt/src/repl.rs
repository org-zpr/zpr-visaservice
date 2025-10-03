use colored::Colorize;

use std::io::{self, Write};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers, read};
use crossterm::terminal::{self, disable_raw_mode, enable_raw_mode};
use crossterm::{cursor, execute};

use crate::error::ZptError;
use crate::parser;
use crate::zmachine::{State, ZMachine};

pub struct Repl {
    machine: ZMachine,
    state: State,
    history: Vec<String>,
}

enum Command {
    Line(String),
    Exit,
}

impl Repl {
    pub fn new() -> Self {
        Repl {
            machine: ZMachine::new(),
            state: State::new(),
            history: Vec::new(),
        }
    }

    /// Run a read-eval-print loop.
    pub fn run(&mut self) -> Result<(), ZptError> {
        let mut input;
        loop {
            match self.read_command()? {
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

            if trimmed.eq_ignore_ascii_case("exit")
                || trimmed.eq_ignore_ascii_case("quit")
                || trimmed.eq_ignore_ascii_case("q")
            {
                break;
            }
            match parser::parse(trimmed) {
                Ok(instruction) => match self.machine.execute(&instruction, &mut self.state) {
                    Ok(_) => {}
                    Err(e) => eprintln!("{}: {}", "Error".red(), e),
                },
                Err(e) => eprintln!("{}: {}", "Error".red(), e),
            };
        }
        Ok(())
    }

    fn read_command(&mut self) -> Result<Command, ZptError> {
        enable_raw_mode()?;
        let res = self.prompt();

        disable_raw_mode()?;

        res
    }

    fn write_prompt(&self) -> Result<(), ZptError> {
        execute!(
            io::stdout(),
            terminal::Clear(terminal::ClearType::CurrentLine)
        )?;
        execute!(io::stdout(), cursor::MoveToColumn(0))?;
        write!(io::stdout(), "{}", "zpt> ".cyan())?;
        io::stdout().flush().unwrap();
        Ok(())
    }

    fn prompt(&mut self) -> Result<Command, ZptError> {
        //let mut input = String::new();

        let mut input: Vec<char> = Vec::new();

        let mut cpos = 0; // next insert point into input.
        let mut hpos = 0;
        let mut prev_input: Option<String> = None;
        let mut prompt = true;
        loop {
            if prompt {
                if prev_input.is_none() {
                    execute!(io::stdout(), terminal::ScrollUp(1))?;
                    execute!(io::stdout(), cursor::MoveToNextLine(1))?;
                }
                self.write_prompt()?;

                match prev_input.take() {
                    Some(s) => {
                        input = s.chars().collect();
                        write!(io::stdout(), "{}", input.iter().collect::<String>())?;
                        cpos = input.len();
                        io::stdout().flush().unwrap();
                    }
                    None => {}
                }
                prompt = false;
            }
            match read()? {
                Event::Key(KeyEvent {
                    code: KeyCode::Char('c'),
                    modifiers: KeyModifiers::CONTROL,
                    kind: _,
                    state: _,
                }) => return Ok(Command::Exit),
                Event::Key(KeyEvent {
                    code: KeyCode::Char(ch),
                    modifiers: _,
                    kind: _,
                    state: _,
                }) => {
                    if cpos == input.len() {
                        input.push(ch);
                        write!(io::stdout(), "{}", ch)?;
                        cpos += 1;
                    } else {
                        input.insert(cpos, ch);

                        // Wipe from cursor forward
                        execute!(
                            io::stdout(),
                            terminal::Clear(terminal::ClearType::UntilNewLine)
                        )?;

                        write!(io::stdout(), "{}", input[cpos..].iter().collect::<String>())?;
                        cpos += 1;

                        // Move cursor back to after inserted char.
                        let back = input.len() - cpos;
                        if back > 0 {
                            execute!(io::stdout(), cursor::MoveLeft(back as u16))?;
                        }
                    }
                    io::stdout().flush().unwrap();
                    hpos = 0;
                }
                Event::Key(KeyEvent {
                    code: KeyCode::Enter,
                    modifiers: _,
                    kind: _,
                    state: _,
                }) => {
                    let input_str = input.iter().collect::<String>();
                    if !input_str.trim().is_empty() {
                        if let Some(last_cmd) = self.history.last() {
                            if last_cmd == &input_str {
                                // Don't add duplicate consecutive entries.
                            } else {
                                self.history.push(input_str.clone());
                            }
                        } else {
                            // Nothing there
                            self.history.push(input_str.clone());
                        }
                        return Ok(Command::Line(input_str));
                    }
                    prompt = true;
                }
                Event::Key(KeyEvent {
                    code: KeyCode::Backspace,
                    modifiers: _,
                    kind: _,
                    state: _,
                }) => {
                    if !input.is_empty() && cpos > 0 {
                        if cpos == input.len() {
                            // Easy, just remove final character.
                            input.pop();
                            cpos -= 1;
                            write!(io::stdout(), "\x08 \x08")?; // Move back, print space, move back again.
                        } else {
                            input.remove(cpos - 1);
                            cpos -= 1;

                            // Wipe from cursor forward
                            execute!(
                                io::stdout(),
                                terminal::Clear(terminal::ClearType::UntilNewLine)
                            )?;

                            // Back up over char we want to remove
                            execute!(io::stdout(), cursor::MoveLeft(1))?;

                            // Reprint remaining input, overwrting the char
                            write!(io::stdout(), "{}", input[cpos..].iter().collect::<String>())?;

                            // Move cursor back to the wiped char position
                            let back = input.len() - cpos;
                            if back > 0 {
                                execute!(io::stdout(), cursor::MoveLeft(back as u16))?;
                            }
                        }
                        io::stdout().flush().unwrap();
                    }
                    hpos = 0;
                }
                Event::Key(KeyEvent {
                    code: KeyCode::Left,
                    modifiers: _,
                    kind: _,
                    state: _,
                }) => {
                    if !input.is_empty() && cpos > 0 {
                        execute!(io::stdout(), cursor::MoveLeft(1))?;
                        io::stdout().flush().unwrap();
                        cpos -= 1;
                    }
                    hpos = 0;
                }
                Event::Key(KeyEvent {
                    code: KeyCode::Right,
                    modifiers: _,
                    kind: _,
                    state: _,
                }) => {
                    if !input.is_empty() && cpos < input.len() {
                        execute!(io::stdout(), cursor::MoveRight(1))?;
                        io::stdout().flush().unwrap();
                        cpos += 1;
                    }
                    hpos = 0;
                }
                Event::Key(KeyEvent {
                    code: KeyCode::Up,
                    modifiers: _,
                    kind: _,
                    state: _,
                }) => {
                    if self.history.is_empty() {
                        continue;
                    }
                    if (hpos + 1) > self.history.len() {
                        continue;
                    }
                    hpos += 1;
                    let hdx = self.history.len() - hpos;
                    let last = &self.history[hdx];
                    prev_input = Some(last.to_string());
                    prompt = true;
                }
                Event::Key(KeyEvent {
                    code: KeyCode::Down,
                    modifiers: _,
                    kind: _,
                    state: _,
                }) => {
                    if hpos == 0 {
                        continue;
                    }
                    hpos -= 1;
                    if hpos == 0 {
                        self.write_prompt()?;
                        input.clear();
                        cpos = 0;
                    }
                    if hpos > 0 {
                        let hdx = self.history.len() - (hpos + 1);
                        let next = &self.history[hdx];
                        prev_input = Some(next.to_string());
                        prompt = true;
                    }
                }

                _ => {}
            }
        }
    }
}
