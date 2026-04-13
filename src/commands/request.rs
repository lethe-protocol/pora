use anyhow::Result;
use clap::Subcommand;
use serde::Serialize;

use crate::output::{self, Format};

#[derive(Subcommand)]
pub enum RequestAction {
    /// Create a bounty + configure repo + set delivery (atomic)
    Submit {
        /// Repository in owner/repo format
        repo: String,
        /// Amount of ROSE to deposit
        #[arg(long, default_value = "1.0")]
        amount: f64,
        /// Trigger mode: on-change, on-push, periodic
        #[arg(long, default_value = "on-change")]
        trigger: String,
        /// Audit mode: static, tee-local, tee-api
        #[arg(long, default_value = "tee-api")]
        mode: String,
        /// Delivery mode: encrypted, github-comment
        #[arg(long, default_value = "encrypted")]
        delivery: String,
    },
    /// List your bounties
    List,
    /// Watch a bounty for audit completion (streams NDJSON events)
    Watch {
        /// Bounty ID
        bounty_id: u64,
    },
    /// Download and decrypt audit results
    Results {
        /// Audit ID
        audit_id: u64,
    },
}

#[derive(Serialize)]
struct BountyInfo {
    bounty_id: u64,
    repo: String,
    amount: String,
    state: String,
    audit_count: u64,
}

pub async fn run(action: RequestAction, format: &Format) -> Result<()> {
    match action {
        RequestAction::Submit { repo, amount, trigger, mode, delivery } => {
            // TODO: implement atomic bounty creation
            let info = serde_json::json!({
                "bounty_id": 0,
                "repo": repo,
                "amount": format!("{} ROSE", amount),
                "trigger": trigger,
                "mode": mode,
                "delivery": delivery,
                "status": "not_implemented",
                "message": "Atomic submit will chain: createBounty + setRepoInfo + setAuditConfig + setDeliveryConfig"
            });
            output::print_success(format, "request.submit", &info);
        }
        RequestAction::List => {
            // TODO: query contract for bounties
            let info = serde_json::json!({
                "bounties": [],
                "status": "not_implemented"
            });
            output::print_success(format, "request.list", &info);
        }
        RequestAction::Watch { bounty_id } => {
            // TODO: poll for audit events, emit NDJSON
            let info = serde_json::json!({
                "bounty_id": bounty_id,
                "status": "not_implemented"
            });
            output::print_success(format, "request.watch", &info);
        }
        RequestAction::Results { audit_id } => {
            // TODO: auto-resolve handle, download, decrypt
            let info = serde_json::json!({
                "audit_id": audit_id,
                "status": "not_implemented"
            });
            output::print_success(format, "request.results", &info);
        }
    }
    Ok(())
}
