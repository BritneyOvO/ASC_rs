use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};

use crate::apk::Options;
use crate::findrefs::{MemberSel, RefQuery};
use crate::{find_refs, get_class_source, list_classes, manifest_xml, Result};

#[derive(Parser)]
#[command(
    name = "asc",
    version,
    about = "ASC tooling entry.",
    after_help = "\
examples:
  asc getclass app.apk Lcom/poc/Main; -o Main.java
  asc getclass app.apk com.poc.Main --threads 16
  asc listclass app.apk -o classes.txt
  asc listclass app.apk --prefix com.poc
  asc getmanifest app.apk -o AndroidManifest.xml
  asc findrefs app.apk string token -o string_refs.txt
  asc findrefs app.apk type com.poc.Main
  asc findrefs app.apk method onCreate --class com.poc.Main
  asc findrefs app.apk method notify --class MainActivity --fuzzy-class -o method_refs.txt
  asc findrefs app.apk field apiKey -o field_refs.txt"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Locate the target class in an APK and decompile it.
    Getclass {
        #[arg(long)]
        debug: bool,
        #[arg(long, alias = "thread", default_value_t = 8)]
        threads: usize,
        #[arg(short, long)]
        output: Option<PathBuf>,
        apk_path: PathBuf,
        dalvik_class: String,
    },
    /// List classes across all DEX entries.
    Listclass {
        #[arg(long)]
        debug: bool,
        #[arg(long, alias = "thread", default_value_t = 8)]
        threads: usize,
        /// Package or class prefix, for example com.poc or Lcom/poc.
        #[arg(long)]
        prefix: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
        apk_path: PathBuf,
    },
    /// Decode AndroidManifest.xml from an APK and print it.
    Getmanifest {
        #[arg(long)]
        debug: bool,
        #[arg(short, long)]
        output: Option<PathBuf>,
        apk_path: PathBuf,
    },
    /// Find code references for a string, type, method, or field.
    Findrefs {
        #[arg(long, global = true)]
        debug: bool,
        #[arg(long, global = true, alias = "thread", default_value_t = 8)]
        threads: usize,
        apk_path: PathBuf,
        #[command(subcommand)]
        query: FindCmd,
    },
}

#[derive(Subcommand)]
enum FindCmd {
    /// Find references to a string. The value is a regular expression.
    String {
        #[arg(short, long)]
        output: Option<PathBuf>,
        value: String,
    },
    /// Find references to a type descriptor or name.
    Type {
        #[arg(short, long)]
        output: Option<PathBuf>,
        value: String,
    },
    /// Find references to methods.
    Method {
        #[arg(short, long)]
        output: Option<PathBuf>,
        name: Option<String>,
        #[arg(long = "class")]
        class_name: Option<String>,
        #[arg(long = "fuzzy-class")]
        fuzzy_class: bool,
    },
    /// Find references to fields.
    Field {
        #[arg(short, long)]
        output: Option<PathBuf>,
        name: Option<String>,
        #[arg(long = "class")]
        class_name: Option<String>,
        #[arg(long = "fuzzy-class")]
        fuzzy_class: bool,
    },
}

pub fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        let mut cmd = Cli::command();
        let _ = cmd.print_long_help();
        println!();
        return 0;
    }
    let cli = match Cli::try_parse_from(std::iter::once(String::from("asc")).chain(args)) {
        Ok(cli) => cli,
        Err(err) => {
            let code = err.exit_code();
            let _ = err.print();
            return code;
        }
    };
    match execute(cli) {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("Error: {err}");
            1
        }
    }
}

fn execute(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Getclass {
            debug,
            threads,
            output,
            apk_path,
            dalvik_class,
        } => {
            let source = get_class_source(&apk_path, &dalvik_class, &Options { threads, debug })?;
            emit(&source, output.as_deref(), true)?;
        }
        Commands::Listclass {
            debug,
            threads,
            prefix,
            output,
            apk_path,
        } => {
            let names = list_classes(&apk_path, prefix.as_deref(), &Options { threads, debug })?;
            let text = if names.is_empty() {
                String::new()
            } else {
                format!("{}\n", names.join("\n"))
            };
            if let Some(path) = output {
                fs::write(path, text)?;
            } else {
                print!("{text}");
                io::stdout().flush()?;
            }
        }
        Commands::Getmanifest {
            debug,
            output,
            apk_path,
        } => {
            let started = std::time::Instant::now();
            let xml = manifest_xml(&apk_path)?;
            emit(&xml, output.as_deref(), true)?;
            if debug {
                eprintln!(
                    "[DEBUG] Total Execution Time: {:.2} us",
                    started.elapsed().as_secs_f64() * 1_000_000.0
                );
            }
        }
        Commands::Findrefs {
            debug,
            threads,
            apk_path,
            query,
        } => {
            let (query, output) = match query {
                FindCmd::String { output, value } => (RefQuery::String(value), output),
                FindCmd::Type { output, value } => (RefQuery::Type(value), output),
                FindCmd::Method {
                    output,
                    name,
                    class_name,
                    fuzzy_class,
                } => (
                    RefQuery::Method(MemberSel {
                        class_name,
                        fuzzy_class,
                        name,
                    }),
                    output,
                ),
                FindCmd::Field {
                    output,
                    name,
                    class_name,
                    fuzzy_class,
                } => (
                    RefQuery::Field(MemberSel {
                        class_name,
                        fuzzy_class,
                        name,
                    }),
                    output,
                ),
            };
            let lines = find_refs(&apk_path, &query, &Options { threads, debug })?;
            let text = if lines.is_empty() {
                String::new()
            } else {
                format!("{}\n", lines.join("\n"))
            };
            emit(&text, output.as_deref(), false)?;
        }
    }
    Ok(())
}

fn emit(text: &str, output: Option<&std::path::Path>, ensure_newline: bool) -> Result<()> {
    let mut owned;
    let text = if ensure_newline && !text.is_empty() && !text.ends_with('\n') {
        owned = String::with_capacity(text.len() + 1);
        owned.push_str(text);
        owned.push('\n');
        owned.as_str()
    } else {
        text
    };
    print!("{text}");
    io::stdout().flush()?;
    if let Some(path) = output {
        fs::write(path, text)?;
    }
    Ok(())
}
