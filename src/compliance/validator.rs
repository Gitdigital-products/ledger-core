use crate::core::event::LedgerEvent;
use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

#[async_trait]
pub trait Rule: Send + Sync {
    async fn evaluate(&self, event: &LedgerEvent, context: &ValidationContext) -> Result<Vec<Violation>>;
    fn get_rule_id(&self) -> &str;
    fn get_severity(&self) -> RuleSeverity;
}

pub struct ComplianceValidator {
    rules: HashMap<String, Box<dyn Rule>>,
    rule_sets: HashMap<String, Vec<String>>,
}

impl ComplianceValidator {
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
            rule_sets: HashMap::new(),
        }
    }
    
    pub fn add_rule(&mut self, rule: Box<dyn Rule>) {
        self.rules.insert(rule.get_rule_id().to_string(), rule);
    }
    
    pub fn create_rule_set(&mut self, name: &str, rule_ids: Vec<&str>) {
        self.rule_sets.insert(
            name.to_string(),
            rule_ids.iter().map(|s| s.to_string()).collect(),
        );
    }
    
    pub async fn validate(&self, event: &LedgerEvent) -> Result<Vec<Violation>> {
        let context = ValidationContext::new();
        let mut violations = Vec::new();
        
        // Apply all rules by default
        for rule in self.rules.values() {
            match rule.evaluate(event, &context).await {
                Ok(mut rule_violations) => violations.append(&mut rule_violations),
                Err(e) => {
                    violations.push(Violation {
                        rule_id: rule.get_rule_id().to_string(),
                        severity: RuleSeverity::Critical,
                        message: format!("Rule evaluation error: {}", e),
                        evidence: serde_json::json!({"error": e.to_string()}),
                    });
                }
            }
        }
        
        Ok(violations)
    }
    
    pub async fn validate_with_rule_set(
        &self,
        event: &LedgerEvent,
        rule_set_name: &str,
    ) -> Result<Vec<Violation>> {
        if let Some(rule_ids) = self.rule_sets.get(rule_set_name) {
            let context = ValidationContext::new();
            let mut violations = Vec::new();
            
            for rule_id in rule_ids {
                if let Some(rule) = self.rules.get(rule_id) {
                    match rule.evaluate(event, &context).await {
                        Ok(mut rule_violations) => violations.append(&mut rule_violations),
                        Err(e) => {
                            violations.push(Violation {
                                rule_id: rule_id.clone(),
                                severity: RuleSeverity::Critical,
                                message: format!("Rule evaluation error: {}", e),
                                evidence: serde_json::json!({"error": e.to_string()}),
                            });
                        }
                    }
                }
            }
            
            Ok(violations)
        } else {
            Err(anyhow::anyhow!("Rule set not found: {}", rule_set_name))
        }
    }
}

pub struct ValidationContext {
    pub additional_data: HashMap<String, Value>,
}

impl ValidationContext {
    pub fn new() -> Self {
        Self {
            additional_data: HashMap::new(),
        }
    }
    
    pub fn with_data(mut self, key: &str, value: Value) -> Self {
        self.additional_data.insert(key.to_string(), value);
        self
    }
}

#[derive(Debug, Clone)]
pub struct Violation {
    pub rule_id: String,
    pub severity: RuleSeverity,
    pub message: String,
    pub evidence: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuleSeverity {
    Warning,
    Error,
    Critical,
}

// Example compliance rules
pub struct AmountLimitRule {
    limit: rust_decimal::Decimal,
    currency: String,
}

impl AmountLimitRule {
    pub fn new(limit: rust_decimal::Decimal, currency: &str) -> Self {
        Self {
            limit,
            currency: currency.to_string(),
        }
    }
}

#[async_trait]
impl Rule for AmountLimitRule {
    async fn evaluate(&self, event: &LedgerEvent, _context: &ValidationContext) -> Result<Vec<Violation>> {
        let mut violations = Vec::new();
        
        if let LedgerEvent::FinancialTransaction(tx) = event {
            if tx.currency == self.currency && tx.amount.amount > self.limit {
                violations.push(Violation {
                    rule_id: self.get_rule_id().to_string(),
                    severity: self.get_severity(),
                    message: format!(
                        "Transaction amount {} {} exceeds limit of {} {}",
                        tx.amount.amount, tx.currency, self.limit, self.currency
                    ),
                    evidence: serde_json::json!({
                        "transaction_amount": tx.amount.amount,
                        "currency": tx.currency,
                        "limit": self.limit,
                    }),
                });
            }
        }
        
        Ok(violations)
    }
    
    fn get_rule_id(&self) -> &str {
        "AMOUNT_LIMIT"
    }
    
    fn get_severity(&self) -> RuleSeverity {
        RuleSeverity::Error
    }
}

pub struct SanctionedCountriesRule {
    sanctioned_countries: Vec<String>,
}

impl SanctionedCountriesRule {
    pub fn new(countries: Vec<&str>) -> Self {
        Self {
            sanctioned_countries: countries.iter().map(|s| s.to_string()).collect(),
        }
    }
}

#[async_trait]
impl Rule for SanctionedCountriesRule {
    async fn evaluate(&self, event: &LedgerEvent, context: &ValidationContext) -> Result<Vec<Violation>> {
        let mut violations = Vec::new();
        
        // Check if any party in the transaction is from a sanctioned country
        // This would typically check against metadata or additional data sources
        
        Ok(violations)
    }
    
    fn get_rule_id(&self) -> &str {
        "SANCTIONED_COUNTRIES"
    }
    
    fn get_severity(&self) -> RuleSeverity {
        RuleSeverity::Critical
    }
}
