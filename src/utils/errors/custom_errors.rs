pub fn exit_process(msg: &str) {
    println!("\n\n(?) Error | Process Exiting Due to:\n");
    println!("{}", msg);
    std::process::exit(0x0100);
}