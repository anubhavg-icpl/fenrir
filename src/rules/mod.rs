use anyhow::{Result, Context};
use regex::Regex;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::Path;
use std::fs;
use tracing::{info, debug, warn};
use yara::Compiler;

use crate::Event;

pub mod sigma;
pub mod patterns;

pub use patterns::DetectionPattern;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub mitre_attack: Vec<String>,
    pub conditions: Vec<Condition>,
    pub actions: Vec<Action>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Condition {
    ProcessName(String),
    ProcessPath(String),
    CommandLine(String),
    ParentProcess(String),
    NetworkConnection { address: String, port: Option<u16> },
    FileAccess { path: String, operation: String },
    RegistryKey(String),
    YaraMatch(String),
    Pattern(DetectionPattern),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    Alert,
    Block,
    Quarantine,
    Log,
    IncreaseRiskScore(f32),
}

pub struct RuleEngine {
    rules: Vec<Rule>,
    yara_rules: Option<yara::Rules>,
    pattern_matcher: patterns::PatternMatcher,
}

impl RuleEngine {
    pub fn new() -> Result<Self> {
        Ok(Self {
            rules: Vec::new(),
            yara_rules: None,
            pattern_matcher: patterns::PatternMatcher::new(),
        })
    }

    pub fn load_rules_from_directory<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();
        
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let file_path = entry.path();
            
            if file_path.extension().and_then(|s| s.to_str()) == Some("yaml") {
                match self.load_rule_file(&file_path) {
                    Ok(rules) => {
                        info!("Loaded {} rules from {:?}", rules.len(), file_path);
                        self.rules.extend(rules);
                    }
                    Err(e) => {
                        warn!("Failed to load rules from {:?}: {}", file_path, e);
                    }
                }
            }
        }

        info!("Loaded {} total rules", self.rules.len());
        Ok(())
    }

    fn load_rule_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<Rule>> {
        let content = fs::read_to_string(path)?;
        let rules: Vec<Rule> = serde_yaml::from_str(&content)?;
        Ok(rules)
    }

    pub fn load_yara_rules<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let mut compiler = Compiler::new()?;
        
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let file_path = entry.path();
            
            if file_path.extension().and_then(|s| s.to_str()) == Some("yar") {
                let content = fs::read_to_string(&file_path)?;
                compiler.add_rules_str(&content)
                    .with_context(|| format!("Failed to compile YARA rules from {:?}", file_path))?;
            }
        }

        self.yara_rules = Some(compiler.compile_rules()?);
        info!("Loaded YARA rules");
        Ok(())
    }

    pub async fn evaluate(&self, event: &Event) -> Result<Vec<Detection>> {
        let mut detections = Vec::new();

        for rule in &self.rules {
            if let Some(detection) = self.evaluate_rule(rule, event).await? {
                detections.push(detection);
            }
        }

        Ok(detections)
    }

    async fn evaluate_rule(&self, rule: &Rule, event: &Event) -> Result<Option<Detection>> {
        let mut matched_conditions = 0;
        let total_conditions = rule.conditions.len();

        for condition in &rule.conditions {
            if self.check_condition(condition, event).await? {
                matched_conditions += 1;
            }
        }

        if matched_conditions == total_conditions && total_conditions > 0 {
            Ok(Some(Detection {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                severity: rule.severity,
                mitre_attack: rule.mitre_attack.clone(),
                event: event.clone(),
                actions: rule.actions.clone(),
            }))
        } else {
            Ok(None)
        }
    }

    async fn check_condition(&self, condition: &Condition, event: &Event) -> Result<bool> {
        match condition {
            Condition::ProcessName(pattern) => {
                if let Event::Process(p) = event {
                    Ok(self.match_pattern(pattern, &p.process_name))
                } else {
                    Ok(false)
                }
            }
            Condition::CommandLine(pattern) => {
                if let Event::Process(p) = event {
                    Ok(self.match_pattern(pattern, &p.command_line))
                } else {
                    Ok(false)
                }
            }
            Condition::NetworkConnection { address, port } => {
                if let Event::Network(n) = event {
                    let addr_match = self.match_pattern(address, &n.remote_address);
                    let port_match = port.map_or(true, |p| p == n.remote_port);
                    Ok(addr_match && port_match)
                } else {
                    Ok(false)
                }
            }
            Condition::FileAccess { path, operation } => {
                if let Event::File(f) = event {
                    let path_match = self.match_pattern(path, &f.file_path);
                    let op_match = operation == "*" || operation == &f.operation;
                    Ok(path_match && op_match)
                } else {
                    Ok(false)
                }
            }
            Condition::Pattern(pattern) => {
                Ok(self.pattern_matcher.matches(pattern, event))
            }
            _ => Ok(false),
        }
    }

    fn match_pattern(&self, pattern: &str, value: &str) -> bool {
        if pattern.contains('*') || pattern.contains('?') {
            let regex_pattern = pattern
                .replace("*", ".*")
                .replace("?", ".");
            if let Ok(regex) = Regex::new(&format!("^{}$", regex_pattern)) {
                regex.is_match(value)
            } else {
                false
            }
        } else {
            pattern.eq_ignore_ascii_case(value)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub mitre_attack: Vec<String>,
    pub event: Event,
    pub actions: Vec<Action>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        let engine = RuleEngine::new().unwrap();
        
        assert!(engine.match_pattern("cmd.exe", "cmd.exe"));
        assert!(engine.match_pattern("*.exe", "powershell.exe"));
        assert!(engine.match_pattern("C:\\Windows\\*", "C:\\Windows\\System32\\cmd.exe"));
        assert!(!engine.match_pattern("*.dll", "notepad.exe"));
    }
}