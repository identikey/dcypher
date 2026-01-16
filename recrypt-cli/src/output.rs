// Output formatting helpers

#[allow(dead_code)] // Some functions are used only in specific commands
use colored::Colorize;
use serde::Serialize;
use std::fmt::Display;

pub fn print_json<T: Serialize>(data: &T) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(data)?;
    println!("{json}");
    Ok(())
}

pub fn print_success(message: impl Display) {
    println!("{} {}", "✓".green(), message);
}

#[allow(dead_code)] // Reserved for future error handling improvements
pub fn print_error(message: impl Display) {
    eprintln!("{} {}", "✗".red(), message);
}

#[allow(dead_code)] // Reserved for future info messages
pub fn print_info(message: impl Display) {
    println!("{} {}", "ℹ".blue(), message);
}
