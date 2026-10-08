mod cli;
mod skills;

fn main() {
    let code = cli::run();
    if code != 0 {
        std::process::exit(code);
    }
}
