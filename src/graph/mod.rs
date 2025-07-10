use anyhow::Result;
use serde::{Serialize, Deserialize};
use surrealdb::{Surreal, engine::local::Mem};
use surrealdb::sql::{thing, Object, Value};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use tracing::{info, debug};

use crate::{Event, etw::parser::{ProcessEvent, NetworkEvent, FileEvent}};

pub struct GraphDatabase {
    db: Surreal<Mem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub id: String,
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub command_line: String,
    pub user: String,
    pub created_at: DateTime<Utc>,
    pub risk_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkNode {
    pub id: String,
    pub address: String,
    pub port: u16,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub connection_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileNode {
    pub id: String,
    pub path: String,
    pub first_seen: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub access_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRelationship {
    pub parent: String,
    pub child: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub process: String,
    pub remote_address: String,
    pub timestamp: DateTime<Utc>,
    pub local_port: u16,
    pub remote_port: u16,
}

impl GraphDatabase {
    pub async fn new() -> Result<Self> {
        let db = Surreal::new::<Mem>(()).await?;
        
        db.use_ns("fenrir").use_db("events").await?;

        db.query("
            DEFINE TABLE process SCHEMAFULL;
            DEFINE FIELD pid ON TABLE process TYPE int;
            DEFINE FIELD ppid ON TABLE process TYPE int;
            DEFINE FIELD name ON TABLE process TYPE string;
            DEFINE FIELD command_line ON TABLE process TYPE string;
            DEFINE FIELD user ON TABLE process TYPE string;
            DEFINE FIELD created_at ON TABLE process TYPE datetime;
            DEFINE FIELD risk_score ON TABLE process TYPE float DEFAULT 0.0;
            DEFINE INDEX idx_pid ON TABLE process COLUMNS pid;

            DEFINE TABLE network SCHEMAFULL;
            DEFINE FIELD address ON TABLE network TYPE string;
            DEFINE FIELD port ON TABLE network TYPE int;
            DEFINE FIELD first_seen ON TABLE network TYPE datetime;
            DEFINE FIELD last_seen ON TABLE network TYPE datetime;
            DEFINE FIELD connection_count ON TABLE network TYPE int DEFAULT 0;

            DEFINE TABLE file SCHEMAFULL;
            DEFINE FIELD path ON TABLE file TYPE string;
            DEFINE FIELD first_seen ON TABLE file TYPE datetime;
            DEFINE FIELD last_modified ON TABLE file TYPE datetime;
            DEFINE FIELD access_count ON TABLE file TYPE int DEFAULT 0;
            DEFINE INDEX idx_path ON TABLE file COLUMNS path;

            DEFINE TABLE spawned SCHEMAFULL;
            DEFINE FIELD in ON TABLE spawned TYPE record(process);
            DEFINE FIELD out ON TABLE spawned TYPE record(process);
            DEFINE FIELD timestamp ON TABLE spawned TYPE datetime;

            DEFINE TABLE connected SCHEMAFULL;
            DEFINE FIELD in ON TABLE connected TYPE record(process);
            DEFINE FIELD out ON TABLE connected TYPE record(network);
            DEFINE FIELD timestamp ON TABLE connected TYPE datetime;
            DEFINE FIELD local_port ON TABLE connected TYPE int;
            DEFINE FIELD remote_port ON TABLE connected TYPE int;

            DEFINE TABLE accessed SCHEMAFULL;
            DEFINE FIELD in ON TABLE accessed TYPE record(process);
            DEFINE FIELD out ON TABLE accessed TYPE record(file);
            DEFINE FIELD timestamp ON TABLE accessed TYPE datetime;
            DEFINE FIELD operation ON TABLE accessed TYPE string;
        ").await?;

        info!("Graph database initialized");

        Ok(Self { db })
    }

    pub async fn store_event(&self, event: &Event) -> Result<()> {
        match event {
            Event::Process(process_event) => {
                self.store_process_event(process_event).await?;
            }
            Event::Network(network_event) => {
                self.store_network_event(network_event).await?;
            }
            Event::File(file_event) => {
                self.store_file_event(file_event).await?;
            }
            Event::Raw { .. } => {
                debug!("Skipping raw event storage");
            }
        }
        Ok(())
    }

    async fn store_process_event(&self, event: &ProcessEvent) -> Result<()> {
        let process_id = format!("process:{}", event.process_id);
        
        let process_node: ProcessNode = self.db
            .create((process_id.clone(),))
            .content(ProcessNode {
                id: process_id.clone(),
                pid: event.process_id,
                ppid: event.parent_process_id,
                name: event.process_name.clone(),
                command_line: event.command_line.clone(),
                user: event.user.clone(),
                created_at: event.timestamp,
                risk_score: 0.0,
            })
            .await?;

        if event.parent_process_id != 0 {
            let parent_id = format!("process:{}", event.parent_process_id);
            
            let _: Value = self.db
                .query("RELATE $parent->spawned->$child SET timestamp = $timestamp")
                .bind(("parent", thing(&parent_id)?))
                .bind(("child", thing(&process_id)?))
                .bind(("timestamp", event.timestamp))
                .await?
                .take(0)?;
        }

        debug!("Stored process event: {}", process_node.name);
        Ok(())
    }

    async fn store_network_event(&self, event: &NetworkEvent) -> Result<()> {
        let network_id = format!("network:{}:{}", event.remote_address, event.remote_port);
        let process_id = format!("process:{}", event.process_id);

        let exists: Option<NetworkNode> = self.db
            .select((network_id.clone(),))
            .await?;

        if let Some(mut node) = exists {
            node.last_seen = event.timestamp;
            node.connection_count += 1;
            let _: NetworkNode = self.db
                .update((network_id.clone(),))
                .content(node)
                .await?;
        } else {
            let _: NetworkNode = self.db
                .create((network_id.clone(),))
                .content(NetworkNode {
                    id: network_id.clone(),
                    address: event.remote_address.clone(),
                    port: event.remote_port,
                    first_seen: event.timestamp,
                    last_seen: event.timestamp,
                    connection_count: 1,
                })
                .await?;
        }

        let _: Value = self.db
            .query("RELATE $process->connected->$network SET timestamp = $timestamp, local_port = $local_port, remote_port = $remote_port")
            .bind(("process", thing(&process_id)?))
            .bind(("network", thing(&network_id)?))
            .bind(("timestamp", event.timestamp))
            .bind(("local_port", event.local_port))
            .bind(("remote_port", event.remote_port))
            .await?
            .take(0)?;

        debug!("Stored network event: {}:{}", event.remote_address, event.remote_port);
        Ok(())
    }

    async fn store_file_event(&self, event: &FileEvent) -> Result<()> {
        let file_id = format!("file:{}", base64::encode(event.file_path.as_bytes()));
        let process_id = format!("process:{}", event.process_id);

        let exists: Option<FileNode> = self.db
            .select((file_id.clone(),))
            .await?;

        if let Some(mut node) = exists {
            node.last_modified = event.timestamp;
            node.access_count += 1;
            let _: FileNode = self.db
                .update((file_id.clone(),))
                .content(node)
                .await?;
        } else {
            let _: FileNode = self.db
                .create((file_id.clone(),))
                .content(FileNode {
                    id: file_id.clone(),
                    path: event.file_path.clone(),
                    first_seen: event.timestamp,
                    last_modified: event.timestamp,
                    access_count: 1,
                })
                .await?;
        }

        let _: Value = self.db
            .query("RELATE $process->accessed->$file SET timestamp = $timestamp, operation = $operation")
            .bind(("process", thing(&process_id)?))
            .bind(("file", thing(&file_id)?))
            .bind(("timestamp", event.timestamp))
            .bind(("operation", &event.operation))
            .await?
            .take(0)?;

        debug!("Stored file event: {}", event.file_path);
        Ok(())
    }

    pub async fn get_process_children(&self, pid: u32) -> Result<Vec<ProcessNode>> {
        let process_id = format!("process:{}", pid);
        
        let children: Vec<ProcessNode> = self.db
            .query("SELECT * FROM process WHERE id IN (SELECT out FROM spawned WHERE in = $parent)")
            .bind(("parent", thing(&process_id)?))
            .await?
            .take(0)?;

        Ok(children)
    }

    pub async fn get_process_connections(&self, pid: u32) -> Result<Vec<NetworkNode>> {
        let process_id = format!("process:{}", pid);
        
        let connections: Vec<NetworkNode> = self.db
            .query("SELECT * FROM network WHERE id IN (SELECT out FROM connected WHERE in = $process)")
            .bind(("process", thing(&process_id)?))
            .await?
            .take(0)?;

        Ok(connections)
    }

    pub async fn get_process_files(&self, pid: u32) -> Result<Vec<FileNode>> {
        let process_id = format!("process:{}", pid);
        
        let files: Vec<FileNode> = self.db
            .query("SELECT * FROM file WHERE id IN (SELECT out FROM accessed WHERE in = $process)")
            .bind(("process", thing(&process_id)?))
            .await?
            .take(0)?;

        Ok(files)
    }

    pub async fn calculate_risk_score(&self, pid: u32) -> Result<f32> {
        let mut risk_score = 0.0;

        let connections = self.get_process_connections(pid).await?;
        for conn in connections {
            if conn.port == 22 || conn.port == 3389 {
                risk_score += 10.0;
            }
            if conn.port == 445 || conn.port == 135 {
                risk_score += 15.0;
            }
            if conn.connection_count > 100 {
                risk_score += 5.0;
            }
        }

        let files = self.get_process_files(pid).await?;
        for file in files {
            if file.path.contains("\\System32\\") || file.path.contains("/etc/") {
                risk_score += 20.0;
            }
            if file.path.ends_with(".exe") || file.path.ends_with(".dll") {
                risk_score += 5.0;
            }
        }

        let children = self.get_process_children(pid).await?;
        if children.len() > 10 {
            risk_score += 25.0;
        }

        Ok(risk_score.min(100.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_graph_database_creation() {
        let db = GraphDatabase::new().await;
        assert!(db.is_ok());
    }
}