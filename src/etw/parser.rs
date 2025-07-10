use anyhow::{Result, Context};
use chrono::{DateTime, Utc};
use ferrisetw::{EventRecord, parser::Parser, schema_locator::SchemaLocator};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

use crate::Event;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub process_id: u32,
    pub parent_process_id: u32,
    pub process_name: String,
    pub command_line: String,
    pub user: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub process_id: u32,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub protocol: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub process_id: u32,
    pub file_path: String,
    pub operation: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEvent {
    pub process_id: u32,
    pub key_path: String,
    pub value_name: String,
    pub operation: String,
    pub timestamp: DateTime<Utc>,
}

pub fn parse_event(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    parser: &Parser
) -> Result<Event> {
    let schema = schema_locator.event_schema(record)
        .context("Failed to get event schema")?;
    
    let parsed = parser.parse_event(record, &schema)
        .context("Failed to parse event")?;

    let event_id = record.event_id();
    let provider_guid = record.provider_guid();
    let timestamp = DateTime::from_timestamp(record.timestamp() as i64, 0)
        .unwrap_or_else(|| Utc::now());

    let event_type = match (provider_guid, event_id) {
        (guid, 1) if is_process_provider(guid) => {
            parse_process_creation(parsed, timestamp)?
        }
        (guid, 3) if is_network_provider(guid) => {
            parse_network_connection(parsed, timestamp)?
        }
        (guid, _) if is_file_provider(guid) => {
            parse_file_operation(parsed, timestamp, event_id)?
        }
        _ => {
            Event::Raw {
                provider: format!("{:?}", provider_guid),
                event_id,
                data: parsed,
                timestamp,
            }
        }
    };

    Ok(event_type)
}

fn is_process_provider(guid: &windows::core::GUID) -> bool {
    *guid == windows::core::GUID::from_values(
        0x22fb2cd6,
        0x0e7b,
        0x422b,
        [0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16],
    )
}

fn is_network_provider(guid: &windows::core::GUID) -> bool {
    *guid == windows::core::GUID::from_values(
        0x7dd42a49,
        0x5329,
        0x4832,
        [0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88],
    )
}

fn is_file_provider(guid: &windows::core::GUID) -> bool {
    *guid == windows::core::GUID::from_values(
        0xedd08927,
        0x9cc4,
        0x4e65,
        [0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89],
    )
}

fn parse_process_creation(
    data: HashMap<String, String>,
    timestamp: DateTime<Utc>
) -> Result<Event> {
    let process_event = ProcessEvent {
        process_id: data.get("ProcessId")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        parent_process_id: data.get("ParentProcessId")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        process_name: data.get("ImageFileName")
            .cloned()
            .unwrap_or_default(),
        command_line: data.get("CommandLine")
            .cloned()
            .unwrap_or_default(),
        user: data.get("UserSID")
            .cloned()
            .unwrap_or_default(),
        timestamp,
    };

    Ok(Event::Process(process_event))
}

fn parse_network_connection(
    data: HashMap<String, String>,
    timestamp: DateTime<Utc>
) -> Result<Event> {
    let network_event = NetworkEvent {
        process_id: data.get("ProcessId")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        local_address: data.get("LocalAddress")
            .cloned()
            .unwrap_or_default(),
        local_port: data.get("LocalPort")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        remote_address: data.get("RemoteAddress")
            .cloned()
            .unwrap_or_default(),
        remote_port: data.get("RemotePort")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        protocol: data.get("Protocol")
            .cloned()
            .unwrap_or_else(|| "TCP".to_string()),
        timestamp,
    };

    Ok(Event::Network(network_event))
}

fn parse_file_operation(
    data: HashMap<String, String>,
    timestamp: DateTime<Utc>,
    event_id: u16
) -> Result<Event> {
    let operation = match event_id {
        12 => "Create",
        13 => "Close", 
        14 => "Read",
        15 => "Write",
        17 => "Delete",
        _ => "Unknown",
    };

    let file_event = FileEvent {
        process_id: data.get("ProcessId")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        file_path: data.get("FileName")
            .cloned()
            .unwrap_or_default(),
        operation: operation.to_string(),
        timestamp,
    };

    Ok(Event::File(file_event))
}