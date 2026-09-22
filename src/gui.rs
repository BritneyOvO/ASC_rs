//! Terminal browser for the same operations the original Tk GUI exposed:
//! class list, decompile, reference search, and the manifest.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use crate::apk::Options;
use crate::findrefs::{MemberSel, RefQuery};
use crate::{find_refs, get_class_source, list_classes, manifest_xml, Result};

pub struct Session {
    pub apk: PathBuf,
    pub threads: usize,
    pub debug: bool,
}

pub fn launch(args: &[String]) -> Result<()> {
    let session = parse_args(args)?;
    eprintln!("ASC  {}", session.apk.display());
    eprintln!("commands: classes [prefix] | open <class> | find string|type|method|field <value> [--class NAME] [--fuzzy-class] | manifest | help | quit");
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    loop {
        eprint!("asc> ");
        let _ = io::stderr().flush();
        let Some(line) = lines.next() else {
            eprintln!();
            break;
        };
        let line = line?;
        match eval(&session, &line)? {
            Eval::Quit => break,
            Eval::Output(text) => {
                print!("{text}");
                if !text.is_empty() && !text.ends_with('\n') {
                    println!();
                }
                let _ = io::stdout().flush();
            }
        }
    }
    Ok(())
}

pub enum Eval {
    Quit,
    Output(String),
}

pub fn eval(session: &Session, line: &str) -> Result<Eval> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(Eval::Output(String::new()));
    }
    let mut parts = split_args(line);
    let cmd = parts.first().map(String::as_str).unwrap_or("");
    match cmd {
        "quit" | "exit" => Ok(Eval::Quit),
        "help" => Ok(Eval::Output(
            "classes [prefix]\nopen <class>\nfind string <pattern>\nfind type <pattern>\nfind method <name> [--class NAME] [--fuzzy-class]\nfind field <name> [--class NAME] [--fuzzy-class]\nmanifest\nquit\n"
                .to_string(),
        )),
        "classes" => {
            let prefix = parts.get(1).map(String::as_str);
            let names = list_classes(
                &session.apk,
                prefix,
                &Options {
                    threads: session.threads,
                    debug: session.debug,
                },
            )?;
            if names.is_empty() {
                Ok(Eval::Output(String::new()))
            } else {
                Ok(Eval::Output(format!("{}\n", names.join("\n"))))
            }
        }
        "open" => {
            let class_name = parts.get(1).map(String::as_str).unwrap_or("");
            if class_name.is_empty() {
                bail!("usage: open <class>");
            }
            let source = get_class_source(
                &session.apk,
                class_name,
                &Options {
                    threads: session.threads,
                    debug: session.debug,
                },
            )?;
            Ok(Eval::Output(source))
        }
        "manifest" => Ok(Eval::Output(manifest_xml(&session.apk)?)),
        "find" => {
            parts.remove(0);
            Ok(Eval::Output(run_find(session, &parts)?))
        }
        other => bail!("unknown command '{other}', type help"),
    }
}

fn run_find(session: &Session, args: &[String]) -> Result<String> {
    if args.is_empty() {
        bail!("usage: find string|type|method|field <value>");
    }
    let kind = args[0].as_str();
    let mut name: Option<String> = None;
    let mut class_name = None;
    let mut fuzzy = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--class" => {
                i += 1;
                class_name = args.get(i).cloned();
                if class_name.is_none() {
                    bail!("--class needs a value");
                }
            }
            "--fuzzy-class" => fuzzy = true,
            other if name.is_none() && !other.starts_with('-') => name = Some(other.to_string()),
            other => bail!("unexpected argument '{other}'"),
        }
        i += 1;
    }
    let options = Options {
        threads: session.threads,
        debug: session.debug,
    };
    let query = match kind {
        "string" => {
            let Some(value) = name else {
                bail!("usage: find string <pattern>");
            };
            RefQuery::String(value)
        }
        "type" => {
            let Some(value) = name else {
                bail!("usage: find type <pattern>");
            };
            RefQuery::Type(value)
        }
        "method" => RefQuery::Method(MemberSel {
            class_name,
            fuzzy_class: fuzzy,
            name,
        }),
        "field" => RefQuery::Field(MemberSel {
            class_name,
            fuzzy_class: fuzzy,
            name,
        }),
        other => bail!("unknown find type '{other}'"),
    };
    let lines = find_refs(&session.apk, &query, &options)?;
    if lines.is_empty() {
        Ok(String::new())
    } else {
        Ok(format!("{}\n", lines.join("\n")))
    }
}

fn parse_args(args: &[String]) -> Result<Session> {
    let mut apk = None;
    let mut threads = 8usize;
    let mut debug = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--gui" | "--gui-foreground" => {}
            "--debug" => debug = true,
            "--threads" | "--thread" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| crate::Error::new("--threads needs a value"))?;
                threads = value
                    .parse()
                    .map_err(|_| crate::Error::new(format!("invalid thread count '{value}'")))?;
            }
            "-h" | "--help" => {
                println!(
                    "\
usage: asc <apk> --gui [--threads N] [--debug]

Open a terminal browser for classes, decompiled source, references, and the manifest."
                );
                std::process::exit(0);
            }
            flag if flag.starts_with('-') => bail!("unknown flag {flag}"),
            value => {
                if apk.is_some() {
                    bail!("unexpected argument {value}");
                }
                apk = Some(PathBuf::from(value));
            }
        }
        index += 1;
    }
    let apk = apk.ok_or_else(|| crate::Error::new("apk path is required"))?;
    if threads == 0 {
        bail!("Worker count must be greater than zero");
    }
    Ok(Session {
        apk,
        threads,
        debug,
    })
}

fn split_args(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    for ch in line.chars() {
        match ch {
            '"' => in_quote = !in_quote,
            ch if ch.is_whitespace() && !in_quote => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            ch => current.push(ch),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}
