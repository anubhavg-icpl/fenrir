use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, debug};

use crate::{Event, graph::GraphDatabase};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub time_window: Duration,
    pub event_patterns: Vec<EventPattern>,
    pub threshold: usize,
    pub severity: crate::rules::Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventPattern {
    pub event_type: String,
    pub conditions: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct CorrelationEngine {
    rules: Vec<CorrelationRule>,
    event_cache: Arc<DashMap<String, VecDeque<Event>>>,
    graph_db: Arc<RwLock<GraphDatabase>>,
    correlation_window: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationAlert {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: crate::rules::Severity,
    pub correlated_events: Vec<Event>,
    pub attack_chain: AttackChain,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    pub stages: Vec<AttackStage>,
    pub confidence: f32,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStage {
    pub stage_name: String,
    pub events: Vec<Event>,
    pub timestamp: DateTime<Utc>,
}

impl CorrelationEngine {
    pub fn new(graph_db: Arc<RwLock<GraphDatabase>>) -> Self {
        Self {
            rules: Vec::new(),
            event_cache: Arc::new(DashMap::new()),
            graph_db,
            correlation_window: Duration::minutes(5),
        }
    }

    pub fn add_rule(&mut self, rule: CorrelationRule) {
        self.rules.push(rule);
    }

    pub async fn find_patterns(&self, event: &Event) -> Result<Vec<CorrelationAlert>> {
        self.cache_event(event).await;
        
        let mut alerts = Vec::new();
        
        for rule in &self.rules {
            if let Some(alert) = self.evaluate_correlation_rule(rule, event).await? {
                alerts.push(alert);
            }
        }

        if let Some(attack_chain) = self.detect_attack_chain(event).await? {
            alerts.push(attack_chain);
        }

        Ok(alerts)
    }

    async fn cache_event(&self, event: &Event) {
        let key = self.get_event_key(event);
        let mut events = self.event_cache.entry(key).or_insert_with(VecDeque::new);
        
        events.push_back(event.clone());
        
        let cutoff_time = Utc::now() - self.correlation_window;
        while let Some(front) = events.front() {
            if self.get_event_timestamp(front) < cutoff_time {
                events.pop_front();
            } else {
                break;
            }
        }
    }

    fn get_event_key(&self, event: &Event) -> String {
        match event {
            Event::Process(p) => format!("process:{}", p.process_id),
            Event::Network(n) => format!("network:{}", n.process_id),
            Event::File(f) => format!("file:{}", f.process_id),
            Event::Raw { provider, .. } => format!("raw:{}", provider),
        }
    }

    fn get_event_timestamp(&self, event: &Event) -> DateTime<Utc> {
        match event {
            Event::Process(p) => p.timestamp,
            Event::Network(n) => n.timestamp,
            Event::File(f) => f.timestamp,
            Event::Raw { timestamp, .. } => *timestamp,
        }
    }

    async fn evaluate_correlation_rule(
        &self,
        rule: &CorrelationRule,
        _trigger_event: &Event
    ) -> Result<Option<CorrelationAlert>> {
        let mut matched_events = Vec::new();
        let cutoff_time = Utc::now() - rule.time_window;

        for pattern in &rule.event_patterns {
            for entry in self.event_cache.iter() {
                let events = entry.value();
                for event in events.iter() {
                    if self.get_event_timestamp(event) >= cutoff_time
                        && self.matches_pattern(event, pattern) {
                        matched_events.push(event.clone());
                    }
                }
            }
        }

        if matched_events.len() >= rule.threshold {
            let alert = CorrelationAlert {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                severity: rule.severity,
                correlated_events: matched_events.clone(),
                attack_chain: self.build_attack_chain(&matched_events).await?,
                timestamp: Utc::now(),
            };
            Ok(Some(alert))
        } else {
            Ok(None)
        }
    }

    fn matches_pattern(&self, event: &Event, pattern: &EventPattern) -> bool {
        let event_type_match = match (&pattern.event_type.as_str(), event) {
            ("process", Event::Process(_)) => true,
            ("network", Event::Network(_)) => true,
            ("file", Event::File(_)) => true,
            _ => false,
        };

        if !event_type_match {
            return false;
        }

        true
    }

    async fn detect_attack_chain(&self, event: &Event) -> Result<Option<CorrelationAlert>> {
        let process_id = match event {
            Event::Process(p) => p.process_id,
            Event::Network(n) => n.process_id,
            Event::File(f) => f.process_id,
            _ => return Ok(None),
        };

        let graph = self.graph_db.read().await;
        
        let risk_score = graph.calculate_risk_score(process_id).await?;
        if risk_score < 50.0 {
            return Ok(None);
        }

        let mut attack_stages = Vec::new();
        
        if let Ok(children) = graph.get_process_children(process_id).await {
            if !children.is_empty() {
                attack_stages.push(AttackStage {
                    stage_name: "Process Spawning".to_string(),
                    events: vec![event.clone()],
                    timestamp: Utc::now(),
                });
            }
        }

        if let Ok(connections) = graph.get_process_connections(process_id).await {
            let suspicious_connections = connections.iter()
                .filter(|c| c.port == 445 || c.port == 3389 || c.port == 22)
                .count();
            
            if suspicious_connections > 0 {
                attack_stages.push(AttackStage {
                    stage_name: "Lateral Movement".to_string(),
                    events: vec![event.clone()],
                    timestamp: Utc::now(),
                });
            }
        }

        if let Ok(files) = graph.get_process_files(process_id).await {
            let sensitive_files = files.iter()
                .filter(|f| f.path.contains("\\System32\\") || 
                           f.path.contains("\\AppData\\") ||
                           f.path.contains("/etc/"))
                .count();
            
            if sensitive_files > 0 {
                attack_stages.push(AttackStage {
                    stage_name: "Data Access".to_string(),
                    events: vec![event.clone()],
                    timestamp: Utc::now(),
                });
            }
        }

        if attack_stages.len() >= 2 {
            let attack_chain = AttackChain {
                stages: attack_stages,
                confidence: risk_score / 100.0,
                mitre_techniques: self.map_to_mitre_techniques(event),
            };

            let alert = CorrelationAlert {
                rule_id: "attack_chain_detection".to_string(),
                rule_name: "Multi-Stage Attack Chain Detected".to_string(),
                severity: crate::rules::Severity::High,
                correlated_events: vec![event.clone()],
                attack_chain,
                timestamp: Utc::now(),
            };

            Ok(Some(alert))
        } else {
            Ok(None)
        }
    }

    async fn build_attack_chain(&self, events: &[Event]) -> Result<AttackChain> {
        let mut stages = Vec::new();
        let mut current_stage = Vec::new();
        let mut last_timestamp = DateTime::<Utc>::MIN_UTC;

        for event in events {
            let timestamp = self.get_event_timestamp(event);
            
            if timestamp - last_timestamp > Duration::seconds(60) && !current_stage.is_empty() {
                stages.push(AttackStage {
                    stage_name: self.infer_stage_name(&current_stage),
                    events: current_stage.clone(),
                    timestamp: last_timestamp,
                });
                current_stage.clear();
            }
            
            current_stage.push(event.clone());
            last_timestamp = timestamp;
        }

        if !current_stage.is_empty() {
            stages.push(AttackStage {
                stage_name: self.infer_stage_name(&current_stage),
                events: current_stage,
                timestamp: last_timestamp,
            });
        }

        let mitre_techniques = events.iter()
            .flat_map(|e| self.map_to_mitre_techniques(e))
            .collect();

        Ok(AttackChain {
            stages,
            confidence: 0.75,
            mitre_techniques,
        })
    }

    fn infer_stage_name(&self, events: &[Event]) -> String {
        let has_process = events.iter().any(|e| matches!(e, Event::Process(_)));
        let has_network = events.iter().any(|e| matches!(e, Event::Network(_)));
        let has_file = events.iter().any(|e| matches!(e, Event::File(_)));

        match (has_process, has_network, has_file) {
            (true, false, false) => "Initial Access".to_string(),
            (true, true, false) => "Command and Control".to_string(),
            (true, false, true) => "Collection".to_string(),
            (true, true, true) => "Exfiltration".to_string(),
            (false, true, false) => "Lateral Movement".to_string(),
            (false, false, true) => "Persistence".to_string(),
            _ => "Unknown Stage".to_string(),
        }
    }

    fn map_to_mitre_techniques(&self, event: &Event) -> Vec<String> {
        match event {
            Event::Process(p) => {
                let mut techniques = Vec::new();
                if p.command_line.contains("powershell") {
                    techniques.push("T1059.001".to_string());
                }
                if p.command_line.contains("cmd") {
                    techniques.push("T1059.003".to_string());
                }
                techniques
            }
            Event::Network(n) => {
                let mut techniques = Vec::new();
                if n.remote_port == 445 {
                    techniques.push("T1021.002".to_string());
                }
                if n.remote_port == 3389 {
                    techniques.push("T1021.001".to_string());
                }
                techniques
            }
            Event::File(f) => {
                let mut techniques = Vec::new();
                if f.file_path.contains("\\Startup\\") {
                    techniques.push("T1547.001".to_string());
                }
                techniques
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_correlation_engine_creation() {
        let graph_db = Arc::new(RwLock::new(GraphDatabase::new().await.unwrap()));
        let engine = CorrelationEngine::new(graph_db);
        assert_eq!(engine.rules.len(), 0);
    }
}