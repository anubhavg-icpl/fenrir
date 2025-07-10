use anyhow::Result;
use clap::Parser;
use fenrir::{
    etw::{EtwEngine, providers::SecurityProviders},
    graph::GraphDatabase,
    rules::RuleEngine,
    correlation::CorrelationEngine,
    Event, FenrirConfig,
};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, error, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "./rules")]
    rules_directory: String,

    #[arg(short, long)]
    yara_rules: Option<String>,

    #[arg(short, long, default_value = "info")]
    log_level: String,

    #[arg(long, default_value = "10000")]
    max_events_per_second: usize,

    #[arg(long, default_value = "5")]
    correlation_window_minutes: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::new(
                std::env::var("RUST_LOG")
                    .unwrap_or_else(|_| format!("fenrir={},ferrisetw=warn", args.log_level))
            ),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Fenrir - Windows Threat Correlation Engine");

    let config = FenrirConfig {
        rules_directory: args.rules_directory,
        yara_rules_directory: args.yara_rules,
        correlation_window_minutes: args.correlation_window_minutes,
        max_events_per_second: args.max_events_per_second,
        ..Default::default()
    };

    let (event_tx, mut event_rx) = mpsc::channel::<Event>(10000);

    info!("Initializing graph database...");
    let graph_db = Arc::new(RwLock::new(GraphDatabase::new().await?));

    info!("Loading detection rules...");
    let mut rule_engine = RuleEngine::new()?;
    if let Err(e) = rule_engine.load_rules_from_directory(&config.rules_directory) {
        warn!("Failed to load rules from directory: {}", e);
    }

    if let Some(yara_dir) = &config.yara_rules_directory {
        if let Err(e) = rule_engine.load_yara_rules(yara_dir) {
            warn!("Failed to load YARA rules: {}", e);
        }
    }

    info!("Initializing correlation engine...");
    let correlation_engine = Arc::new(CorrelationEngine::new(graph_db.clone()));

    info!("Setting up ETW providers...");
    let mut etw_engine = EtwEngine::new(event_tx)?;
    
    etw_engine.add_provider(SecurityProviders::microsoft_windows_security_auditing())?;
    etw_engine.add_provider(SecurityProviders::microsoft_windows_kernel_process())?;
    etw_engine.add_provider(SecurityProviders::microsoft_windows_kernel_network())?;
    etw_engine.add_provider(SecurityProviders::microsoft_windows_threat_intelligence())?;
    etw_engine.add_provider(SecurityProviders::microsoft_windows_powershell())?;
    
    let etw_handle = tokio::spawn(async move {
        if let Err(e) = etw_engine.start().await {
            error!("ETW engine error: {}", e);
        }
    });

    info!("Starting event processing loop...");
    let mut event_count = 0u64;
    let mut last_report = std::time::Instant::now();

    while let Some(event) = event_rx.recv().await {
        event_count += 1;

        {
            let graph = graph_db.write().await;
            if let Err(e) = graph.store_event(&event).await {
                error!("Failed to store event in graph: {}", e);
            }
        }

        match rule_engine.evaluate(&event).await {
            Ok(detections) => {
                for detection in detections {
                    info!(
                        "DETECTION: {} - {} [{:?}]",
                        detection.rule_name,
                        detection.rule_id,
                        detection.severity
                    );
                }
            }
            Err(e) => {
                error!("Rule evaluation error: {}", e);
            }
        }

        match correlation_engine.find_patterns(&event).await {
            Ok(alerts) => {
                for alert in alerts {
                    info!(
                        "CORRELATION ALERT: {} - {} events correlated [{:?}]",
                        alert.rule_name,
                        alert.correlated_events.len(),
                        alert.severity
                    );
                    
                    for stage in &alert.attack_chain.stages {
                        info!("  Attack Stage: {} at {}", stage.stage_name, stage.timestamp);
                    }
                    
                    if !alert.attack_chain.mitre_techniques.is_empty() {
                        info!("  MITRE Techniques: {:?}", alert.attack_chain.mitre_techniques);
                    }
                }
            }
            Err(e) => {
                error!("Correlation engine error: {}", e);
            }
        }

        if last_report.elapsed().as_secs() >= 60 {
            info!("Processed {} events in the last minute", event_count);
            event_count = 0;
            last_report = std::time::Instant::now();
        }
    }

    etw_handle.await?;
    info!("Fenrir shutdown complete");
    Ok(())
}