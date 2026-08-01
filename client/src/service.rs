use std::{fs, path::Path, process::Command};

use anyhow::Context;

pub enum Action {
    Install,
    Uninstall,
    Start,
    Stop,
    Status,
}

#[cfg(target_os = "linux")]
pub fn run(action: Action) -> anyhow::Result<()> {
    linux(action)
}
#[cfg(target_os = "macos")]
pub fn run(action: Action) -> anyhow::Result<()> {
    macos(action)
}
#[cfg(target_os = "windows")]
pub fn run(action: Action) -> anyhow::Result<()> {
    windows(action)
}
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn run(_: Action) -> anyhow::Result<()> {
    anyhow::bail!("service management is not supported on this OS")
}

#[cfg(target_os = "linux")]
fn linux(action: Action) -> anyhow::Result<()> {
    let config = directories::BaseDirs::new()
        .context("could not find home directory")?
        .config_dir()
        .join("systemd/user");
    let unit = config.join("clipmesh.service");
    match action {
        Action::Install => {
            fs::create_dir_all(&config)?;
            let executable = std::env::current_exe()?;
            fs::write(
                &unit,
                format!(
                    "[Unit]\nDescription=ClipMesh clipboard sync\nAfter=graphical-session.target network-online.target\n\n[Service]\nExecStart={} daemon run\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n",
                    systemd_escape(&executable)
                ),
            )?;
            command("systemctl", &["--user", "daemon-reload"])?;
            command("systemctl", &["--user", "enable", "clipmesh.service"])?;
            println!("Installed user service. Start it with `clipmesh service start`.");
        }
        Action::Uninstall => {
            let _ = command(
                "systemctl",
                &["--user", "disable", "--now", "clipmesh.service"],
            );
            if unit.exists() {
                fs::remove_file(unit)?;
            }
            command("systemctl", &["--user", "daemon-reload"])?;
            println!("Uninstalled user service.");
        }
        Action::Start => command("systemctl", &["--user", "start", "clipmesh.service"])?,
        Action::Stop => command("systemctl", &["--user", "stop", "clipmesh.service"])?,
        Action::Status => {
            let status = Command::new("systemctl")
                .args(["--user", "is-active", "clipmesh.service"])
                .status()?;
            println!(
                "{}",
                if status.success() {
                    "running"
                } else {
                    "stopped"
                }
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos(action: Action) -> anyhow::Result<()> {
    let home = directories::BaseDirs::new()
        .context("could not find home directory")?
        .home_dir()
        .to_path_buf();
    let dir = home.join("Library/LaunchAgents");
    let plist = dir.join("io.clipmesh.client.plist");
    let uid = String::from_utf8(Command::new("id").arg("-u").output()?.stdout)?
        .trim()
        .to_owned();
    let domain = format!("gui/{uid}");
    match action {
        Action::Install => {
            fs::create_dir_all(&dir)?;
            let exe = std::env::current_exe()?;
            fs::write(
                &plist,
                format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>Label</key><string>io.clipmesh.client</string><key>ProgramArguments</key><array><string>{}</string><string>daemon</string><string>run</string></array><key>RunAtLoad</key><false/><key>KeepAlive</key><true/></dict></plist>"#,
                    xml(&exe.to_string_lossy())
                ),
            )?;
            println!("Installed LaunchAgent. Start it with `clipmesh service start`.");
        }
        Action::Uninstall => {
            let _ = Command::new("launchctl")
                .args(["bootout", &format!("{domain}/io.clipmesh.client")])
                .status();
            if plist.exists() {
                fs::remove_file(plist)?;
            }
        }
        Action::Start => command(
            "launchctl",
            &["bootstrap", &domain, plist.to_str().unwrap()],
        )?,
        Action::Stop => command(
            "launchctl",
            &["bootout", &format!("{domain}/io.clipmesh.client")],
        )?,
        Action::Status => {
            let status = Command::new("launchctl")
                .args(["print", &format!("{domain}/io.clipmesh.client")])
                .status()?;
            println!(
                "{}",
                if status.success() {
                    "running"
                } else {
                    "stopped"
                }
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows(action: Action) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let target = format!("\"{}\" daemon run", exe.display());
    match action {
        Action::Install => {
            command(
                "schtasks",
                &[
                    "/Create", "/SC", "ONLOGON", "/TN", "ClipMesh", "/TR", &target, "/F",
                ],
            )?;
            println!("Installed login task. Start it with `clipmesh service start`.");
        }
        Action::Uninstall => command("schtasks", &["/Delete", "/TN", "ClipMesh", "/F"])?,
        Action::Start => command("schtasks", &["/Run", "/TN", "ClipMesh"])?,
        Action::Stop => command("schtasks", &["/End", "/TN", "ClipMesh"])?,
        Action::Status => {
            let status = Command::new("schtasks")
                .args(["/Query", "/TN", "ClipMesh"])
                .status()?;
            println!(
                "{}",
                if status.success() {
                    "installed"
                } else {
                    "not installed"
                }
            );
        }
    }
    Ok(())
}

fn command(program: &str, arguments: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(program)
        .args(arguments)
        .status()
        .with_context(|| format!("could not run {program}"))?;
    if !status.success() {
        anyhow::bail!("{program} exited with {status}");
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn systemd_escape(path: &Path) -> String {
    path.to_string_lossy().replace(' ', "\\x20")
}
#[cfg(target_os = "macos")]
fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
