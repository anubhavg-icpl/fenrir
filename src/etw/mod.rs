use anyhow::Result;
use ferrisetw::{
    parser::Parser,
    provider::{Provider, EventFilter},
    schema_locator::SchemaLocator,
    trace::{UserTrace, TraceTrait},
    EventRecord,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, error, debug};

pub mod providers;
pub mod parser;

use crate::Event;

pub struct EtwEngine {
    trace: UserTrace,
    event_sender: mpsc::Sender<Event>,
    providers: Vec<Provider>,
}

impl EtwEngine {
    pub fn new(event_sender: mpsc::Sender<Event>) -> Result<Self> {
        let trace = UserTrace::new()?;
        
        Ok(Self {
            trace,
            event_sender,
            providers: Vec::new(),
        })
    }

    pub fn add_provider(&mut self, provider: Provider) -> Result<()> {
        self.trace.enable_provider(provider.clone())?;
        self.providers.push(provider);
        Ok(())
    }

    pub fn add_kernel_provider(&mut self, flags: u32) -> Result<()> {
        self.trace.enable_kernel_provider(flags)?;
        Ok(())
    }

    pub async fn start(mut self) -> Result<()> {
        let schema_locator = SchemaLocator::new();
        let parser = Parser::new(Arc::new(schema_locator));
        let sender = self.event_sender.clone();

        let callback = move |record: &EventRecord, schema_locator: &SchemaLocator| {
            match parser::parse_event(record, schema_locator, &parser) {
                Ok(event) => {
                    let sender = sender.clone();
                    tokio::spawn(async move {
                        if let Err(e) = sender.send(event).await {
                            error!("Failed to send event: {}", e);
                        }
                    });
                }
                Err(e) => {
                    debug!("Failed to parse event: {}", e);
                }
            }
        };

        info!("Starting ETW trace session");
        
        self.trace.start()?;
        
        loop {
            match self.trace.process_one() {
                Ok(_) => {},
                Err(e) => {
                    error!("Error processing ETW event: {}", e);
                    break;
                }
            }
        }

        self.trace.stop()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_etw_engine_creation() {
        let (tx, _rx) = mpsc::channel(1000);
        let engine = EtwEngine::new(tx);
        assert!(engine.is_ok());
    }
}