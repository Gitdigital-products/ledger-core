use serde::{Deserialize, Serialize};
use validator::Validate;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(tag = "event_type")]
pub enum LedgerEvent {
    #[serde(rename = "financial_transaction")]
    FinancialTransaction(FinancialTransaction),
    
    #[serde(rename = "compliance_alert")]
    ComplianceAlert(ComplianceAlert),
    
    #[serde(rename = "account_creation")]
    AccountCreation(AccountCreation),
    
    #[serde(rename = "balance_adjustment")]
    BalanceAdjustment(BalanceAdjustment),
    
    #[serde(rename = "audit_log")]
    AuditLog(AuditLog),
}

impl LedgerEvent {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            LedgerEvent::FinancialTransaction(tx) => tx.validate()
                .map_err(|e| format!("Financial transaction validation failed: {:?}", e)),
            LedgerEvent::AccountCreation(acct) => acct.validate()
                .map_err(|e| format!("Account creation validation failed: {:?}", e)),
            _ => Ok(()),
        }
    }
    
    pub fn get_entity_id(&self) -> String {
        match self {
            LedgerEvent::FinancialTransaction(tx) => tx.transaction_id.clone(),
            LedgerEvent::ComplianceAlert(alert) => alert.alert_id.clone(),
            LedgerEvent::AccountCreation(acct) => acct.account_id.clone(),
            LedgerEvent::BalanceAdjustment(adj) => adj.adjustment_id.clone(),
            LedgerEvent::AuditLog(log) => log.log_id.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct FinancialTransaction {
    #[validate(length(min = 1))]
    pub transaction_id: String,
    
    pub from_account: String,
    pub to_account: String,
    
    #[validate]
    pub amount: Money,
    
    pub currency: String,
    pub description: String,
    
    #[serde(default)]
    pub metadata: serde_json::Value,
    
    pub timestamp: chrono::DateTime<chrono::Utc>,
    
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct Money {
    #[validate(range(min = 0))]
    pub amount: rust_decimal::Decimal,
    
    #[validate(length(equal = 3))]
    pub currency_code: String,
    
    #[serde(default)]
    pub precision: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAlert {
    pub alert_id: String,
    pub rule_id: String,
    pub severity: AlertSeverity,
    pub description: String,
    pub affected_entities: Vec<String>,
    pub evidence: serde_json::Value,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AccountCreation {
    #[validate(length(min = 1))]
    pub account_id: String,
    
    pub account_type: AccountType,
    pub owner_id: String,
    
    #[validate]
    pub initial_balance: Money,
    
    pub compliance_level: ComplianceLevel,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccountType {
    Asset,
    Liability,
    Equity,
    Revenue,
    Expense,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceLevel {
    LowRisk,
    MediumRisk,
    HighRisk,
    Sanctioned,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceAdjustment {
    pub adjustment_id: String,
    pub account_id: String,
    pub reason: AdjustmentReason,
    pub amount: Money,
    pub reference: String,
    pub authorized_by: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdjustmentReason {
    Correction,
    WriteOff,
    Revaluation,
    Regulatory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub log_id: String,
    pub action: String,
    pub actor: String,
    pub resource: String,
    pub changes: serde_json::Value,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}
