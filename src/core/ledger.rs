use crate::core::event::LedgerEvent;
use crate::compliance::validator::ComplianceValidator;
use crate::storage::append_only::AppendOnlyStorage;
use crate::utils::crypto::generate_hash_chain;
use std::sync::Arc;
use tokio::sync::RwLock;
use thiserror::Error;
use tracing::{info, error};

#[derive(Error, Debug)]
pub enum LedgerError {
    #[error("Compliance validation failed: {0}")]
    ComplianceViolation(String),
    #[error("Storage error: {0}")]
    StorageError(#[from] crate::storage::append_only::StorageError),
    #[error("Event validation failed: {0}")]
    ValidationError(String),
    #[error("Ledger is sealed, no new entries allowed")]
    LedgerSealed,
}

pub struct DigitalLedger {
    storage: Arc<dyn AppendOnlyStorage>,
    validator: Arc<ComplianceValidator>,
    is_sealed: RwLock<bool>,
    chain_id: String,
}

impl DigitalLedger {
    pub async fn new(
        storage: Arc<dyn AppendOnlyStorage>,
        validator: Arc<ComplianceValidator>,
        chain_id: String,
    ) -> Result<Self, LedgerError> {
        Ok(Self {
            storage,
            validator,
            is_sealed: RwLock::new(false),
            chain_id,
        })
    }

    pub async fn append_event(
        &self,
        event: LedgerEvent,
        metadata: Option<serde_json::Value>,
    ) -> Result<String, LedgerError> {
        // Check if ledger is sealed
        if *self.is_sealed.read().await {
            return Err(LedgerError::LedgerSealed);
        }

        // Validate event structure
        event.validate()?;

        // Run compliance checks
        self.validator.validate(&event).await.map_err(|e| {
            LedgerError::ComplianceViolation(format!("Compliance check failed: {}", e))
        })?;

        // Generate event ID with cryptographic hash
        let event_hash = generate_hash_chain(&event)?;
        
        // Create immutable record
        let record = LedgerRecord {
            event_id: event_hash.clone(),
            event,
            metadata: metadata.unwrap_or_default(),
            timestamp: chrono::Utc::now(),
            previous_hash: self.storage.get_latest_hash().await?,
            chain_id: self.chain_id.clone(),
            signature: None, // Would be populated with actual signing
        };

        // Store append-only
        self.storage.append(record).await?;

        info!("Event appended successfully: {}", event_hash);
        Ok(event_hash)
    }

    pub async fn verify_integrity(&self) -> Result<bool, LedgerError> {
        self.storage.verify_chain().await.map_err(|e| e.into())
    }

    pub async fn get_audit_trail(
        &self,
        entity_id: Option<&str>,
        start_time: Option<chrono::DateTime<chrono::Utc>>,
        end_time: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<LedgerRecord>, LedgerError> {
        self.storage
            .query_records(entity_id, start_time, end_time)
            .await
            .map_err(|e| e.into())
    }

    pub async fn seal_ledger(&self) -> Result<(), LedgerError> {
        let mut sealed = self.is_sealed.write().await;
        *sealed = true;
        info!("Ledger sealed at: {}", chrono::Utc::now());
        Ok(())
    }

    pub async fn get_merkle_root(&self) -> Result<String, LedgerError> {
        self.storage.get_merkle_root().await.map_err(|e| e.into())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LedgerRecord {
    pub event_id: String,
    pub event: LedgerEvent,
    pub metadata: serde_json::Value,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub previous_hash: Option<String>,
    pub chain_id: String,
    pub signature: Option<String>,
}
