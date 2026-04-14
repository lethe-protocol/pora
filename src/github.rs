use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::config;

#[derive(Debug, Serialize, Deserialize, Default)]
struct InstallationCache {
    /// Map of "owner/repo" → installation ID
    installations: HashMap<String, u64>,
}

// checks: none
// effects: none
// returns: path to ~/.pora/cache/installations.json
fn cache_path() -> PathBuf {
    config::config_dir().join("cache").join("installations.json")
}

// checks: cache file exists and is valid JSON
// effects: reads file
// returns: cached installation ID if found
fn read_cache(owner: &str, repo: &str) -> Option<u64> {
    let path = cache_path();
    let content = std::fs::read_to_string(path).ok()?;
    let cache: InstallationCache = serde_json::from_str(&content).ok()?;
    let key = format!("{}/{}", owner, repo);
    cache.installations.get(&key).copied()
}

// checks: none
// effects: writes cache file, creates parent dirs if needed
// returns: Ok on success
fn write_cache(owner: &str, repo: &str, installation_id: u64) -> Result<()> {
    let path = cache_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut cache = if path.exists() {
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        InstallationCache::default()
    };

    let key = format!("{}/{}", owner, repo);
    cache.installations.insert(key, installation_id);
    let json = serde_json::to_string_pretty(&cache)?;
    std::fs::write(&path, json)?;
    Ok(())
}

// checks: GH_TOKEN env var is set, GitHub API is reachable
// effects: HTTP GET to GitHub API
// returns: installation ID from GitHub App installation for this repo
// WHY: this uses the /repos/{owner}/{repo}/installation endpoint which requires
//      the GH_TOKEN to have access to the GitHub App's installations.
//      A generic PAT may not work — GitHub App auth is preferred.
async fn github_api_lookup(owner: &str, repo: &str) -> Result<u64> {
    let token = std::env::var("GH_TOKEN")
        .or_else(|_| std::env::var("GITHUB_TOKEN"))
        .context(
            "GH_TOKEN or GITHUB_TOKEN not set. Cannot auto-detect installation ID.",
        )?;

    let client = reqwest::Client::new();
    let url = format!(
        "https://api.github.com/repos/{}/{}/installation",
        owner, repo
    );
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "pora-cli")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "GitHub API returned {}: {}. Ensure the pora GitHub App is installed on {}/{}",
            status,
            body,
            owner,
            repo
        );
    }

    let json: serde_json::Value = resp.json().await?;
    json["id"]
        .as_u64()
        .context("GitHub API response missing 'id' field")
}

/// Check if a GitHub repo is public by making an unauthenticated API call.
// checks: GitHub API is reachable
// effects: HTTP GET to GitHub API (no auth required for public repos)
// returns: true if public, false if private/not found
// WHY: public repos don't need any auth for TEE to clone.
//      This enables the --access auto mode to skip GitHub App for open source repos.
pub async fn check_repo_visibility(owner: &str, repo: &str) -> Result<bool> {
    let client = reqwest::Client::new();
    let url = format!("https://api.github.com/repos/{}/{}", owner, repo);
    let resp = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "pora-cli")
        .send()
        .await
        .context("GitHub API request failed")?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        // 404 means either private or non-existent. Cannot distinguish without auth.
        return Ok(false);
    }

    if !resp.status().is_success() {
        anyhow::bail!("GitHub API returned {}", resp.status());
    }

    let json: serde_json::Value = resp.json().await?;
    // WHY: GitHub API returns {"private": false} for public repos.
    Ok(!json["private"].as_bool().unwrap_or(true))
}

/// Resolve GitHub App installation ID using the 5-level fallback (AD-4).
///
/// Priority:
/// 1. explicit_id (from --installation-id flag)
/// 2. GH_INSTALLATION_ID env var
/// 3. ~/.pora/cache/installations.json
/// 4. GitHub API: GET /repos/{owner}/{repo}/installation
/// 5. Actionable error
// checks: at least one resolution method succeeds
// effects: may write to cache on successful API lookup
// returns: installation ID
pub async fn resolve_installation_id(
    owner: &str,
    repo: &str,
    explicit_id: Option<u64>,
) -> Result<u64> {
    // Level 1: explicit flag
    if let Some(id) = explicit_id {
        // Cache it for future use
        let _ = write_cache(owner, repo, id);
        return Ok(id);
    }

    // Level 2: environment variable
    if let Ok(env_id) = std::env::var("GH_INSTALLATION_ID") {
        if let Ok(id) = env_id.parse::<u64>() {
            let _ = write_cache(owner, repo, id);
            return Ok(id);
        }
    }

    // Level 3: local cache
    if let Some(id) = read_cache(owner, repo) {
        return Ok(id);
    }

    // Level 4: GitHub API (opportunistic)
    match github_api_lookup(owner, repo).await {
        Ok(id) => {
            let _ = write_cache(owner, repo, id);
            return Ok(id);
        }
        Err(e) => {
            // Log but fall through to actionable error
            eprintln!("GitHub API lookup failed: {}", e);
        }
    }

    // Level 5: actionable error
    anyhow::bail!(
        "INSTALLATION_NOT_FOUND: No GitHub App installation found for {}/{}. \
         Fix: install the pora GitHub App at https://github.com/apps/pora-testnet, \
         or pass --installation-id <id>, or set GH_INSTALLATION_ID env var.",
        owner,
        repo
    )
}
