use anyhow::Result;
use clap::Subcommand;

use crate::output::{self, Format};

#[derive(Subcommand)]
pub enum PerformerAction {
    /// Initialize performer config (wallet, provider, API key)
    Init {
        /// LLM provider: anthropic, openai, openrouter
        #[arg(long, default_value = "anthropic")]
        provider: String,
        /// Auto-detect Claude Code OAuth token
        #[arg(long)]
        use_claude_login: bool,
    },
    /// Start autonomous audit loop (emits NDJSON events)
    Start {
        /// Run one audit cycle then exit
        #[arg(long)]
        once: bool,
    },
    /// Show earnings, reputation, and active jobs
    Status,
}

pub async fn run(action: PerformerAction, format: &Format) -> Result<()> {
    match action {
        PerformerAction::Init { provider, use_claude_login } => {
            let mut api_key_source = "manual".to_string();

            if use_claude_login {
                // Auto-detect Claude Code OAuth token
                if let Some(home) = dirs::home_dir() {
                    let creds_path = home.join(".claude").join(".credentials.json");
                    if creds_path.exists() {
                        let creds: serde_json::Value = serde_json::from_str(
                            &std::fs::read_to_string(&creds_path)?
                        )?;
                        if let Some(oauth) = creds.get("claudeAiOauth") {
                            if let Some(token) = oauth.get("accessToken").and_then(|t| t.as_str()) {
                                let sub_type = oauth.get("subscriptionType")
                                    .and_then(|s| s.as_str())
                                    .unwrap_or("unknown");
                                api_key_source = format!("claude-oauth ({})", sub_type);

                                let info = serde_json::json!({
                                    "provider": provider,
                                    "api_key_source": api_key_source,
                                    "token_prefix": &token[..20],
                                    "subscription": sub_type,
                                    "message": "Claude Code OAuth token detected. No additional API costs."
                                });
                                output::print_success(format, "performer.init", &info);
                                return Ok(());
                            }
                        }
                    }
                }
                anyhow::bail!("Claude Code credentials not found at ~/.claude/.credentials.json. Run 'claude' and log in first.");
            }

            let info = serde_json::json!({
                "provider": provider,
                "api_key_source": api_key_source,
                "status": "not_implemented",
                "message": "Set ANTHROPIC_API_KEY or use --use-claude-login"
            });
            output::print_success(format, "performer.init", &info);
        }
        PerformerAction::Start { once } => {
            let info = serde_json::json!({
                "mode": if once { "single" } else { "continuous" },
                "status": "not_implemented",
                "message": "Autonomous audit loop will: poll → claim → TEE audit → submit → collect"
            });
            output::print_success(format, "performer.start", &info);
        }
        PerformerAction::Status => {
            let info = serde_json::json!({
                "status": "not_implemented",
                "message": "Will show: earnings, reputation score, active jobs, API spend"
            });
            output::print_success(format, "performer.status", &info);
        }
    }
    Ok(())
}
