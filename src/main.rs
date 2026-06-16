use std::process::Stdio;
use tokio::io::{self, AsyncWriteExt};
use tokio::process::Command;

#[tokio::main]

async fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (command, command_args) = args
        .split_first()
        .expect("usage: vex-mcp <command> [args...]");

    eprintln!("{:?} {:?}", command, command_args);

    let mut child = Command::new(command)
        .args(command_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let mut child_stdin = child.stdin.take().expect("child stdin was piped");
    let mut child_stdout = child.stdout.take().expect("child stdout was piped");

    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    let client_to_server = io::copy(&mut stdin, &mut child_stdin);
    let server_to_client = io::copy(&mut child_stdout, &mut stdout);

    tokio::try_join!(client_to_server, server_to_client)?;

    child_stdin.shutdown().await?;
    child.wait().await?;

    Ok(())
}
