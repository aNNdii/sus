fn main() {
    std::process::exit(sus::daemon_main(std::env::args_os().skip(1).collect()))
}
