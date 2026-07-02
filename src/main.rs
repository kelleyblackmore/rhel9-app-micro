use std::path::Path;

use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info};

use secureledger::auth::seed_users;
use secureledger::config::Config;
use secureledger::db;
use secureledger::observe::install_metrics;
use secureledger::ratelimit::RateLimiter;
use secureledger::state::AppState;
use secureledger::build_router;

#[tokio::main]
async fn main() {
    init_tracing();

    let config = Config::from_env();
    info!(bind = %config.bind_addr, db = %config.db_path, "starting SecureLedger");

    // Ensure the parent directory of the DB path exists. On a read-only rootfs
    // this may fail; log and continue so the error surfaces at connect time
    // (readiness will report not-ready rather than crashing on boot).
    ensure_db_dir(&config.db_path);

    // Install metrics recorder (must happen before any metric is recorded).
    let metrics_handle = install_metrics();

    // Build DB pool and schema.
    let pool = match db::build_pool(&config.db_path) {
        Ok(p) => p,
        Err(e) => {
            error!(error = %e, "failed to build database pool");
            std::process::exit(1);
        }
    };
    if let Err(e) = db::init_schema(&pool) {
        error!(error = %e, "failed to initialize schema");
        std::process::exit(1);
    }

    let users = seed_users();
    let rate_limiter = RateLimiter::new(config.rate_limit_per_min);
    let bind_addr = config.bind_addr.clone();

    let state = AppState::new(config, pool, users, rate_limiter);
    let app = build_router(state, metrics_handle);

    let listener = match TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, addr = %bind_addr, "failed to bind");
            std::process::exit(1);
        }
    };
    info!(addr = %bind_addr, "listening");

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        error!(error = %e, "server error");
        std::process::exit(1);
    }

    info!("shutdown complete");
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,secureledger=info,tower_http=warn"));

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(false)
        .init();
}

fn ensure_db_dir(db_path: &str) {
    if db_path == ":memory:" {
        return;
    }
    if let Some(parent) = Path::new(db_path).parent() {
        if !parent.as_os_str().is_empty() {
            match std::fs::create_dir_all(parent) {
                Ok(_) => info!(dir = %parent.display(), "ensured DB directory"),
                Err(e) => error!(
                    error = %e,
                    dir = %parent.display(),
                    "could not create DB directory (read-only rootfs?); continuing"
                ),
            }
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { info!("received SIGINT"); }
        _ = terminate => { info!("received SIGTERM"); }
    }
}
