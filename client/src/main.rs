mod api;
mod clipboard;
mod commands;
mod file_transfer;
mod history;
mod service;
mod state;
mod sync;
mod tui;

use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand};
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "clipmesh",
    version,
    about = "End-to-end encrypted clipboard sync"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the foreground TUI (the default when no command is given).
    Tui,
    /// Pair this installation with one server. The code is read interactively.
    Pair {
        #[arg(long)]
        server: String,
        #[arg(long)]
        name: String,
        #[arg(long, hide = true)]
        code: Option<String>,
    },
    Status,
    /// Encrypt and send a file. Pass PATH, or pipe stdin with --filename.
    SendFile {
        /// File to send. Omit to read file content from stdin.
        path: Option<PathBuf>,
        /// Filename for piped stdin. With PATH, overrides its basename.
        #[arg(long)]
        filename: Option<String>,
        /// Media type stored inside the encrypted manifest.
        #[arg(long, default_value = "application/octet-stream")]
        media_type: String,
    },
    #[command(subcommand)]
    Channel(ChannelCommand),
    Route(RouteArgs),
    Pause(PauseArgs),
    #[command(subcommand)]
    History(HistoryCommand),
    /// Forget the paired server and credential-store secrets.
    Forget,
    #[command(subcommand)]
    Service(ServiceCommand),
    #[command(subcommand, hide = true)]
    Daemon(DaemonCommand),
}

#[derive(Subcommand)]
enum ChannelCommand {
    List,
    Create {
        #[arg(long)]
        name: String,
    },
    Join {
        id: Uuid,
    },
    Leave {
        id: Uuid,
    },
    Delete {
        id: Uuid,
    },
}
#[derive(Args)]
struct RouteArgs {
    id: Uuid,
    #[arg(long, action=ArgAction::Set)]
    send: Option<bool>,
    #[arg(long, action=ArgAction::Set)]
    receive: Option<bool>,
}
#[derive(Args)]
struct PauseArgs {
    #[arg(long, action=ArgAction::Set)]
    sending: Option<bool>,
    #[arg(long, action=ArgAction::Set)]
    receiving: Option<bool>,
}
#[derive(Subcommand)]
enum HistoryCommand {
    List,
    Show {
        id: Uuid,
        #[arg(long)]
        reveal: bool,
    },
    Copy {
        id: Uuid,
    },
    Resend {
        id: Uuid,
    },
    Export {
        id: Uuid,
        #[arg(long)]
        output: PathBuf,
    },
    Delete {
        id: Uuid,
    },
    Clear,
}
#[derive(Subcommand)]
enum ServiceCommand {
    Install,
    Uninstall,
    Start,
    Stop,
    Status,
}
#[derive(Subcommand)]
enum DaemonCommand {
    Run,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let paths = state::Paths::discover()?;
    match cli.command.unwrap_or(Command::Tui) {
        Command::Tui => tui::run(paths).await,
        Command::Pair { server, name, code } => commands::pair(&paths, &server, &name, code).await,
        Command::Status => commands::status(&paths).await,
        Command::SendFile {
            path,
            filename,
            media_type,
        } => commands::send_file(&paths, path.as_deref(), filename.as_deref(), &media_type).await,
        Command::Channel(command) => match command {
            ChannelCommand::List => commands::list_channels(&paths).await,
            ChannelCommand::Create { name } => commands::create_channel(&paths, &name).await,
            ChannelCommand::Join { id } => commands::join_channel(&paths, id).await,
            ChannelCommand::Leave { id } => commands::leave_channel(&paths, id, false).await,
            ChannelCommand::Delete { id } => commands::leave_channel(&paths, id, true).await,
        },
        Command::Route(value) => commands::set_route(&paths, value.id, value.send, value.receive),
        Command::Pause(value) => commands::set_pause(&paths, value.sending, value.receiving),
        Command::History(command) => match command {
            HistoryCommand::List => commands::list_history(&paths),
            HistoryCommand::Show { id, reveal } => commands::show_history(&paths, id, reveal),
            HistoryCommand::Copy { id } => commands::copy_history(&paths, id),
            HistoryCommand::Resend { id } => commands::resend_history(&paths, id).await,
            HistoryCommand::Export { id, output } => {
                commands::export_history(&paths, id, &output).await
            }
            HistoryCommand::Delete { id } => history::delete(&paths.history_db, id),
            HistoryCommand::Clear => history::clear(&paths.history_db),
        },
        Command::Forget => commands::forget(&paths).await,
        Command::Service(value) => service::run(match value {
            ServiceCommand::Install => service::Action::Install,
            ServiceCommand::Uninstall => service::Action::Uninstall,
            ServiceCommand::Start => service::Action::Start,
            ServiceCommand::Stop => service::Action::Stop,
            ServiceCommand::Status => service::Action::Status,
        }),
        Command::Daemon(DaemonCommand::Run) => daemon(paths).await,
    }
}

async fn daemon(paths: state::Paths) -> anyhow::Result<()> {
    let file = tracing_appender::rolling::never(&paths.data_dir, "clipmesh.log");
    let (writer, guard) = tracing_appender::non_blocking(file);
    let _guard = guard;
    tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "clipmesh_client=info".into()),
        )
        .init();
    let engine = sync::start(paths)?;
    tracing::info!("ClipMesh service started");
    tokio::signal::ctrl_c().await?;
    engine.stop().await
}
