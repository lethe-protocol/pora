use anyhow::Result;
use clap::Subcommand;

use crate::output::{self, Format};

#[derive(Subcommand)]
pub enum SystemAction {
    /// Check config, connectivity, wallet balance, registration
    Doctor,
    /// Show wallet address, network, registration status
    Whoami,
}

pub async fn run(action: SystemAction, format: &Format) -> Result<()> {
    match action {
        SystemAction::Doctor => {
            let config_dir = dirs::home_dir()
                .map(|h| h.join(".pora"))
                .unwrap_or_default();

            let config_exists = config_dir.join("config.toml").exists();
            let delivery_key_exists = config_dir.join("delivery.key").exists();
            let performer_config_exists = config_dir.join("performer.json").exists();

            let info = serde_json::json!({
                "checks": {
                    "config_dir": {
                        "path": config_dir.to_string_lossy(),
                        "exists": config_dir.exists(),
                    },
                    "config_file": {
                        "status": if config_exists { "ok" } else { "missing" },
                        "action": if config_exists { "none" } else { "Run: pora performer init" },
                    },
                    "delivery_key": {
                        "status": if delivery_key_exists { "ok" } else { "missing" },
                        "action": if delivery_key_exists { "none" } else { "Auto-generated on first pora request submit" },
                    },
                    "performer_config": {
                        "status": if performer_config_exists { "ok" } else { "not_configured" },
                        "action": if performer_config_exists { "none" } else { "Run: pora performer init" },
                    },
                    "network": {
                        "status": "not_implemented",
                        "rpc": "https://testnet.sapphire.oasis.io",
                    },
                }
            });
            output::print_success(format, "system.doctor", &info);
        }
        SystemAction::Whoami => {
            let info = serde_json::json!({
                "status": "not_implemented",
                "message": "Will show: wallet address, network, balance, performer registration"
            });
            output::print_success(format, "system.whoami", &info);
        }
    }
    Ok(())
}
