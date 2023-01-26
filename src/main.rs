extern crate clamd_client;

use std::env;
use anyhow::Result;

fn main() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    let mut clamd = clamd_client::Clamd::new()?;
    if args.len() == 2 {
        println!("{}", match &args[1].to_lowercase()[..] {
            "ping" => clamd.ping()?,
            "version" => clamd.version()?,
            "reload" => clamd.reload()?,
            "shutdown" => {clamd.shutdown()?; String::from("Shutdown succeeded")},
            other => format!("Command not found: {}", other),
        });
    } else if args.len() == 3 {
        println!("{}", match &args[1].to_lowercase()[..] {
            "scan" => clamd.scan(&args[2])?,
            "instream" => clamd.instream_scan(&args[2], None)?,
            other => format!("Command not found: {}", other),
        });
    }

    Ok(())
}
