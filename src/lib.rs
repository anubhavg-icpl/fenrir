pub mod etw;
pub mod graph;
pub mod rules;
pub mod correlation;

use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    Process(etw::parser::ProcessEvent),
    Network(etw::parser::NetworkEvent),
    File(etw::parser::FileEvent),
    Raw {
        provider: String,
        event_id: u16,
        data: HashMap<String, String>,
        timestamp: DateTime<Utc>,
    },
}

#[derive(Debug, Clone)]
pub struct FenrirConfig {
    pub etw_providers: Vec<String>,
    pub rules_directory: String,
    pub yara_rules_directory: Option<String>,
    pub correlation_window_minutes: u64,
    pub max_events_per_second: usize,
    pub graph_db_path: Option<String>,
}

impl Default for FenrirConfig {
    fn default() -> Self {
        Self {
            etw_providers: vec![
                "Microsoft-Windows-Security-Auditing".to_string(),
                "Microsoft-Windows-Kernel-Process".to_string(),
                "Microsoft-Windows-Kernel-Network".to_string(),
            ],
            rules_directory: "./rules".to_string(),
            yara_rules_directory: None,
            correlation_window_minutes: 5,
            max_events_per_second: 10000,
            graph_db_path: None,
        }
    }
}