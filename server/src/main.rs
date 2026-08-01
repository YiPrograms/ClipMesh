use clipmesh_server::{build, config::Config};
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "clipmesh_server=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::from_env()?;
    let listen = config.listen;
    let (app, state) = build(config).await?;
    state.spawn_cleanup();
    let listener = TcpListener::bind(listen).await?;
    tracing::info!(%listen, "ClipMesh server listening");
    axum::serve(listener, app).await?;
    Ok(())
}
