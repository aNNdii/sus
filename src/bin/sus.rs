fn main() {
    std::process::exit(sus::client_main(std::env::args_os().skip(1).collect()))
}
