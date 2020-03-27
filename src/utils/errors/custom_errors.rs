
pub fn exit_process(log_level: &str, msg: &str) {
    let _dashes = "-".repeat(msg.len());
    let _user_message = format!(r#"
    (?) {} | Process Exiting Due To:
    {}
    {}
    "#, log_level, _dashes, msg);

    println!("{}", _user_message);
    std::process::exit(0x0100);
}