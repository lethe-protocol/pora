"""pora CLI — human-friendly interface to the security audit market."""

import json
import sys

import click

from pora.client import PoraClient


def _client(**kwargs) -> PoraClient:
    return PoraClient(**{k: v for k, v in kwargs.items() if v})


@click.group()
@click.version_option()
def main():
    """pora — Security audit market. Audit. Earn. Forget."""
    pass


# ── Key management ──


@main.command()
@click.option("--output", "-o", default=".", help="Directory for keypair files")
def keygen(output):
    """Generate X25519 delivery keypair."""
    priv_path, pub_hex = PoraClient.generate_keypair(output)
    click.echo(f"Private key: {priv_path}")
    click.echo(f"Public key:  {pub_hex}")
    click.echo("⚠ Back up your private key. Lost keys = unrecoverable audit results.")


# ── Bounty commands ──


@main.group()
def bounty():
    """Manage bounties."""
    pass


@bounty.command("create")
@click.argument("repo")
@click.option("--amount", "-a", type=float, default=1.0, help="ROSE to deposit")
@click.option("--duration", "-d", type=int, default=7, help="Duration in days")
@click.option("--standing/--one-time", default=True, help="Repeating bounty")
@click.option("--installation-id", "-i", type=int, required=True, help="GitHub App installation ID")
@click.option("--trigger", "-t", default="on-change", help="Trigger mode: on-change, periodic, both")
@click.option("--period-days", type=int, default=0, help="Days between periodic audits")
@click.option("--private-key", envvar="PORA_PRIVATE_KEY", help="Wallet private key")
@click.option("--rpc", envvar="PORA_RPC_URL", default="", help="Sapphire RPC URL")
@click.option("--contract", envvar="PORA_CONTRACT", default="", help="LetheMarket address")
def bounty_create(repo, amount, duration, standing, installation_id, trigger, period_days, private_key, rpc, contract):
    """Create a bounty for REPO (owner/repo format).

    Example: pora bounty create lethe-protocol/lethe-market --amount 1 -i 122858796
    """
    client = _client(private_key=private_key, rpc_url=rpc, contract_address=contract)

    click.echo(f"Creating bounty for {repo}...")
    bounty_id = client.create_bounty(repo, amount_rose=amount, duration_days=duration, standing=standing)
    click.echo(f"Bounty #{bounty_id} created.")

    click.echo(f"Linking repo info...")
    client.set_repo_info(bounty_id, repo=repo, installation_id=installation_id)
    click.echo(f"Repo linked.")

    click.echo(f"Setting audit config ({trigger})...")
    client.set_audit_config(bounty_id, trigger=trigger, period_days=period_days)
    click.echo(f"Config set.")

    click.echo(f"\n✓ Bounty #{bounty_id} is live. ROFL worker will pick it up on next poll cycle.")


@bounty.command("list")
@click.option("--all", "show_all", is_flag=True, help="Include closed/cancelled bounties")
@click.option("--rpc", envvar="PORA_RPC_URL", default="", help="Sapphire RPC URL")
@click.option("--contract", envvar="PORA_CONTRACT", default="", help="LetheMarket address")
def bounty_list(show_all, rpc, contract):
    """List bounties on the market."""
    client = _client(rpc_url=rpc, contract_address=contract)
    bounties = client.list_bounties(only_open=not show_all)

    if not bounties:
        click.echo("No bounties found.")
        return

    states = {0: "Open", 1: "Completed", 2: "Cancelled"}
    for b in bounties:
        rose = client.w3.from_wei(b.amount, "ether")
        standing = "standing" if b.standing else "one-time"
        click.echo(f"  #{b.id}  {states.get(b.state, '?')}  {rose} ROSE  {standing}  audits={b.audit_count}")


@bounty.command("fund")
@click.argument("bounty_id", type=int)
@click.option("--amount", "-a", type=float, required=True, help="ROSE to add")
@click.option("--private-key", envvar="PORA_PRIVATE_KEY")
@click.option("--rpc", envvar="PORA_RPC_URL", default="")
@click.option("--contract", envvar="PORA_CONTRACT", default="")
def bounty_fund(bounty_id, amount, private_key, rpc, contract):
    """Top up a standing bounty."""
    client = _client(private_key=private_key, rpc_url=rpc, contract_address=contract)
    tx = client.fund_bounty(bounty_id, amount_rose=amount)
    click.echo(f"Funded bounty #{bounty_id} with {amount} ROSE. tx={tx}")


@bounty.command("cancel")
@click.argument("bounty_id", type=int)
@click.option("--private-key", envvar="PORA_PRIVATE_KEY")
@click.option("--rpc", envvar="PORA_RPC_URL", default="")
@click.option("--contract", envvar="PORA_CONTRACT", default="")
def bounty_cancel(bounty_id, private_key, rpc, contract):
    """Cancel a bounty and reclaim funds."""
    client = _client(private_key=private_key, rpc_url=rpc, contract_address=contract)
    tx = client.cancel_bounty(bounty_id)
    click.echo(f"Cancelled bounty #{bounty_id}. tx={tx}")


# ── Delivery commands ──


@main.group()
def delivery():
    """Encrypted delivery management."""
    pass


@delivery.command("setup")
@click.argument("bounty_id", type=int)
@click.option("--key", "-k", required=True, help="Path to public key file or hex string")
@click.option("--private-key", envvar="PORA_PRIVATE_KEY")
@click.option("--rpc", envvar="PORA_RPC_URL", default="")
@click.option("--contract", envvar="PORA_CONTRACT", default="")
def delivery_setup(bounty_id, key, private_key, rpc, contract):
    """Register encryption key for a bounty."""
    client = _client(private_key=private_key, rpc_url=rpc, contract_address=contract)

    import os
    if os.path.isfile(key):
        pub_hex = open(key).read().strip()
    else:
        pub_hex = key

    tx = client.set_delivery_key(bounty_id, pub_key_hex=pub_hex)
    click.echo(f"Delivery key set for bounty #{bounty_id}. tx={tx}")


# ── Audit commands ──


@main.group()
def audit():
    """View and manage audits."""
    pass


@audit.command("list")
@click.option("--bounty-id", "-b", type=int, help="Filter by bounty ID")
@click.option("--rpc", envvar="PORA_RPC_URL", default="")
@click.option("--contract", envvar="PORA_CONTRACT", default="")
def audit_list(bounty_id, rpc, contract):
    """List audits."""
    client = _client(rpc_url=rpc, contract_address=contract)
    count = client.audit_count()

    if count == 0:
        click.echo("No audits found.")
        return

    results = {0: "Findings", 1: "NoFindings"}
    states = {0: "Pending", 1: "Verified", 2: "Disputed"}

    for i in range(1, count + 1):
        a = client.get_audit(i)
        if bounty_id and a.bounty_id != bounty_id:
            continue
        rose = client.w3.from_wei(a.payout, "ether")
        click.echo(
            f"  #{a.id}  bounty={a.bounty_id}  {states.get(a.state, '?')}  "
            f"{results.get(a.result, '?')}  findings={a.finding_count}  payout={rose} ROSE"
        )


@audit.command("show")
@click.argument("audit_id", type=int)
@click.option("--rpc", envvar="PORA_RPC_URL", default="")
@click.option("--contract", envvar="PORA_CONTRACT", default="")
def audit_show(audit_id, rpc, contract):
    """Show detailed audit info."""
    client = _client(rpc_url=rpc, contract_address=contract)
    a = client.get_audit(audit_id)
    d = client.get_delivery(audit_id)
    s = client.get_settlement(audit_id)

    click.echo(f"Audit #{audit_id}")
    click.echo(f"  Bounty:    #{a.bounty_id}")
    click.echo(f"  Result:    {'Findings' if a.result == 0 else 'NoFindings'} ({a.finding_count} findings)")
    click.echo(f"  Payout:    {client.w3.from_wei(a.payout, 'ether')} ROSE")
    click.echo(f"  State:     {['Pending', 'Verified', 'Disputed'][a.state]}")
    click.echo(f"  Commit:    0x{a.commit_hash[:20].hex()}")
    click.echo(f"  PoE:       0x{a.poe_hash.hex()[:16]}...")
    click.echo(f"  Delivery:  {'Ready' if d.delivery_status == 1 else 'None'}")

    click.echo(f"  Settlement:")
    click.echo(f"    Performer:   {s['performer']}")
    click.echo(f"    Exec fee:    {client.w3.from_wei(s['execution_fee'], 'ether')} ROSE")
    click.echo(f"    Finding:     {client.w3.from_wei(s['finding_bonus'], 'ether')} ROSE")
    click.echo(f"    Patch:       {client.w3.from_wei(s['patch_bonus'], 'ether')} ROSE")
    click.echo(f"    Regression:  {client.w3.from_wei(s['regression_bonus'], 'ether')} ROSE")
    click.echo(f"    Claimed:     {client.w3.from_wei(s['claimed_amount'], 'ether')} ROSE")


# ── Market overview ──


@main.command()
@click.option("--rpc", envvar="PORA_RPC_URL", default="")
@click.option("--contract", envvar="PORA_CONTRACT", default="")
def status(rpc, contract):
    """Show market status."""
    client = _client(rpc_url=rpc, contract_address=contract)
    bc = client.bounty_count()
    ac = client.audit_count()
    pp = client.payout_policy()

    click.echo(f"pora market status")
    click.echo(f"  Contract:  {client.contract_address}")
    click.echo(f"  Network:   {client.rpc_url}")
    click.echo(f"  Bounties:  {bc}")
    click.echo(f"  Audits:    {ac}")
    click.echo(f"  Policy:    {pp.execution_fee_bps//100}% exec / {pp.finding_bonus_bps//100}% finding / {pp.patch_bonus_bps//100}% patch / {pp.regression_bonus_bps//100}% regression")
    click.echo(f"  Standing:  {pp.standing_percent_bps//100}% per audit, min {client.w3.from_wei(pp.minimum_payout, 'ether')} ROSE")


if __name__ == "__main__":
    main()
