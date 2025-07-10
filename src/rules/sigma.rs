use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    pub title: String,
    pub id: String,
    pub status: String,
    pub description: String,
    pub references: Vec<String>,
    pub tags: Vec<String>,
    pub logsource: LogSource,
    pub detection: Detection,
    pub falsepositives: Vec<String>,
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    pub product: Option<String>,
    pub service: Option<String>,
    pub category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub selection: HashMap<String, serde_yaml::Value>,
    pub condition: String,
}

pub struct SigmaConverter;

impl SigmaConverter {
    pub fn new() -> Self {
        Self
    }

    pub fn convert_sigma_to_fenrir_rule(&self, sigma: &SigmaRule) -> Result<crate::rules::Rule> {
        let severity = match sigma.level.as_str() {
            "critical" => crate::rules::Severity::Critical,
            "high" => crate::rules::Severity::High,
            "medium" => crate::rules::Severity::Medium,
            "low" => crate::rules::Severity::Low,
            _ => crate::rules::Severity::Info,
        };

        let mut conditions = Vec::new();
        
        for (field, value) in &sigma.detection.selection {
            let condition = self.convert_selection_to_condition(field, value)?;
            conditions.push(condition);
        }

        let mitre_attack = sigma.tags.iter()
            .filter(|tag| tag.starts_with("attack."))
            .map(|tag| tag.replace("attack.", ""))
            .collect();

        Ok(crate::rules::Rule {
            id: sigma.id.clone(),
            name: sigma.title.clone(),
            description: sigma.description.clone(),
            severity,
            mitre_attack,
            conditions,
            actions: vec![crate::rules::Action::Alert],
        })
    }

    fn convert_selection_to_condition(
        &self,
        field: &str,
        value: &serde_yaml::Value
    ) -> Result<crate::rules::Condition> {
        let value_str = match value {
            serde_yaml::Value::String(s) => s.clone(),
            serde_yaml::Value::Number(n) => n.to_string(),
            serde_yaml::Value::Sequence(seq) => {
                seq.first()
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            }
            _ => String::new(),
        };

        let condition = match field {
            "CommandLine" | "commandline" => {
                crate::rules::Condition::CommandLine(value_str)
            }
            "Image" | "image" | "ProcessName" => {
                crate::rules::Condition::ProcessName(value_str)
            }
            "ParentImage" | "parentimage" => {
                crate::rules::Condition::ParentProcess(value_str)
            }
            "TargetFilename" | "targetfilename" => {
                crate::rules::Condition::FileAccess {
                    path: value_str,
                    operation: "*".to_string(),
                }
            }
            "DestinationIp" | "dst_ip" => {
                crate::rules::Condition::NetworkConnection {
                    address: value_str,
                    port: None,
                }
            }
            _ => {
                crate::rules::Condition::CommandLine(format!("{}:{}", field, value_str))
            }
        };

        Ok(condition)
    }
}