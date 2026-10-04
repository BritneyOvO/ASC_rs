use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use clap::{CommandFactory, Parser, Subcommand};

use asc_abc::{class_names, class_text, find_members, find_strings, find_types, is_abc};
use asc_apk::{
    dump_apk, find_refs, get_class_source, list_classes, manifest_xml, Engine, Error, MemberSel,
    Options, RefQuery, Result,
};
use asc_hap::{self, Query};

#[derive(Parser)]
#[command(
    name = "asc",
    version,
    about = "ASC tooling entry.",
    after_help = "\
examples:
  asc getclass app.apk Lcom/poc/Main; -o Main.java
  asc getclass app.apk com.poc.Main --threads 16
  asc getclass app.apk com.poc.Main --engine smali
  asc listclass app.apk -o classes.txt
  asc listclass app.apk --prefix com.poc
  asc getmanifest app.apk -o AndroidManifest.xml
  asc dump app.apk -o output
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

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum EngineArg {
    /// Structured Java via ddc.
    Ddc,
    /// Baksmali text.
    Smali,
}

fn engine_of(arg: EngineArg) -> Engine {
    match arg {
        EngineArg::Ddc => Engine::Ddc,
        EngineArg::Smali => Engine::Smali,
    }
}

fn apk_options(threads: usize, debug: bool, engine: Engine) -> Options {
    Options {
        threads,
        debug,
        engine,
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Locate the target class in an APK and decompile it.
    Getclass {
        #[arg(long)]
        debug: bool,
        #[arg(long, alias = "thread", default_value_t = 8)]
        threads: usize,
        /// `ddc` writes Java. `smali` writes baksmali text.
        #[arg(long, value_enum, default_value = "ddc")]
        engine: EngineArg,
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
    /// Decompile every class in an APK into a Java tree.
    Dump {
        #[arg(long)]
        debug: bool,
        #[arg(long, alias = "thread", default_value_t = 8)]
        threads: usize,
        /// Decompiler for method bodies. Defaults to ddc.
        #[arg(long, value_enum, default_value = "ddc")]
        engine: EngineArg,
        #[arg(short, long)]
        output: PathBuf,
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
            engine,
            output,
            apk_path,
            dalvik_class,
        } => {
            let source = if let Some(data) = read_abc(&apk_path)? {
                class_text(&data, &dalvik_class).map_err(abc_err)?
            } else if hap_file(&apk_path)? {
                asc_hap::get_class_source(&apk_path, &dalvik_class, &hap_options(threads, debug))
                    .map_err(hap_err)?
            } else {
                get_class_source(
                    &apk_path,
                    &dalvik_class,
                    &apk_options(threads, debug, engine_of(engine)),
                )?
            };
            emit(&source, output.as_deref(), true)?;
        }
        Commands::Listclass {
            debug,
            threads,
            prefix,
            output,
            apk_path,
        } => {
            let names = if let Some(data) = read_abc(&apk_path)? {
                class_names(&data, prefix.as_deref()).map_err(abc_err)?
            } else if hap_file(&apk_path)? {
                asc_hap::list_classes(&apk_path, prefix.as_deref(), &hap_options(threads, debug))
                    .map_err(hap_err)?
            } else {
                list_classes(
                    &apk_path,
                    prefix.as_deref(),
                    &apk_options(threads, debug, Engine::Ddc),
                )?
            };
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
            if read_abc(&apk_path)?.is_some() {
                return Err(Error::new("ABC files have no AndroidManifest.xml"));
            }
            if hap_file(&apk_path)? {
                let text = asc_hap::module_json(&apk_path).map_err(hap_err)?;
                emit(&text, output.as_deref(), true)?;
                return Ok(());
            }
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
        Commands::Dump {
            debug,
            threads,
            engine,
            output,
            apk_path,
        } => {
            if read_abc(&apk_path)?.is_some() {
                return Err(Error::new("dump does not read ABC files"));
            }
            if hap_file(&apk_path)? {
                let stats = asc_hap::dump_hap(&apk_path, &output, &hap_options(threads, debug))
                    .map_err(hap_err)?;
                eprintln!(
                    "dumped {} classes ({} errors) -> {}",
                    stats.classes,
                    stats.errors,
                    output.display()
                );
                return Ok(());
            }
            let started = std::time::Instant::now();
            let stats = dump_apk(
                &apk_path,
                &output,
                &apk_options(threads, debug, engine_of(engine)),
            )?;
            eprintln!(
                "dumped {} classes ({} errors) -> {}",
                stats.classes,
                stats.errors,
                output.display()
            );
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
            let lines = if let Some(data) = read_abc(&apk_path)? {
                abc_refs(&data, &apk_path, &query)?
            } else if hap_file(&apk_path)? {
                asc_hap::find_refs(&apk_path, hap_query(&query), &hap_options(threads, debug))
                    .map_err(hap_err)?
            } else {
                find_refs(
                    &apk_path,
                    &query,
                    &apk_options(threads, debug, Engine::Ddc),
                )?
            };
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

fn read_abc(path: &Path) -> Result<Option<Vec<u8>>> {
    let mut file = File::open(path).map_err(|source| Error::IoPath {
        action: "open",
        path: path.display().to_string(),
        source,
    })?;
    let mut magic = [0u8; 8];
    let read = file.read(&mut magic).map_err(|source| Error::IoPath {
        action: "open",
        path: path.display().to_string(),
        source,
    })?;
    if read < 8 || !is_abc(&magic) {
        return Ok(None);
    }
    let mut data = Vec::from(magic);
    file.read_to_end(&mut data)
        .map_err(|source| Error::IoPath {
            action: "open",
            path: path.display().to_string(),
            source,
        })?;
    Ok(Some(data))
}

fn abc_err(err: asc_abc::Error) -> Error {
    Error::new(err.to_string())
}

fn hap_err(err: asc_hap::Error) -> Error {
    Error::new(err.to_string())
}

fn hap_file(path: &Path) -> Result<bool> {
    asc_hap::is_hap(path).map_err(hap_err)
}

fn hap_options(threads: usize, debug: bool) -> asc_hap::Options {
    asc_hap::Options { threads, debug }
}

fn hap_query(query: &RefQuery) -> Query<'_> {
    match query {
        RefQuery::String(pattern) => Query::String(pattern),
        RefQuery::Type(pattern) => Query::Type(pattern),
        RefQuery::Method(sel) => Query::Method {
            name: sel.name.as_deref(),
            class_name: sel.class_name.as_deref(),
        },
        RefQuery::Field(sel) => Query::Field {
            name: sel.name.as_deref(),
            class_name: sel.class_name.as_deref(),
        },
    }
}

fn abc_refs(data: &[u8], path: &Path, query: &RefQuery) -> Result<Vec<String>> {
    let file = path.display().to_string();
    match query {
        RefQuery::String(pattern) => find_strings(data, &file, pattern).map_err(abc_err),
        RefQuery::Type(pattern) => find_types(data, &file, pattern).map_err(abc_err),
        RefQuery::Method(sel) => abc_members(data, &file, true, sel),
        RefQuery::Field(sel) => abc_members(data, &file, false, sel),
    }
}

fn abc_members(data: &[u8], file: &str, methods: bool, sel: &MemberSel) -> Result<Vec<String>> {
    let pattern = sel.name.as_deref().unwrap_or(".*");
    find_members(data, file, methods, pattern, sel.class_name.as_deref()).map_err(abc_err)
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
