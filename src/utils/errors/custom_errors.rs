/// # Custom Errors - Exit Process
/// A convenient method for lightweight usage to exit the program
/// due to a condition.
/// 
/// # Example
/// ```ignore
/// exit_process("Info", "Foo Sucks");      // Logs an informational level
/// exit_process("Warn", "Low Memory");     // Logs a warning level message
/// exit_process("Error", "Foo Failed");    // Logs an error
/// ```
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