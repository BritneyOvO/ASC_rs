fn main() {
    let code = asc::cli::run();
    if code != 0 {
        std::process::exit(code);
    }
}
