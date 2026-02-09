"""CLI entry-point for Command Guardian."""

from __future__ import annotations

import sys
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from . import classifier, policy, receipts, tokens, verify
from .runner import run as runner_run

app = typer.Typer(
    name="guardian",
    help="Command Guardian — a seatbelt for your terminal.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()

# ─────────────────────────── guardian run ──────────────────────────────────


@app.command("run")
def cmd_run(command: List[str] = typer.Argument(..., help="Command to run through enforcement.")):
    """Run a command through enforcement."""
    raw = " ".join(command)
    result = runner_run(raw)

    if result.decision == "DENY":
        console.print(f"\n[bold red]✘ DENIED[/bold red]  intent={result.intent}")
        console.print(f"  Reason: {result.reason}")
        if result.receipt:
            # Check for suggestion via policy
            intent = result.intent
            pol = policy.evaluate(raw, intent)
            if pol.suggestion:
                console.print(f"  💡 Suggestion: {pol.suggestion}")
            console.print(f"  Receipt: {result.receipt.get('hash', '')[:16]}…")
        raise typer.Exit(code=1)

    # ALLOW
    console.print(f"[bold green]✔ ALLOWED[/bold green]  intent={result.intent}")
    if result.output:
        sys.stdout.write(result.output)
    raise typer.Exit(code=result.exit_code)


# ─────────────────────────── guardian policy [show] ───────────────────────

policy_app = typer.Typer(
    name="policy",
    help="Policy commands.",
    invoke_without_command=True,
    no_args_is_help=False,
)
app.add_typer(policy_app, name="policy", help="Policy commands.")


def _print_policy_summary() -> None:
    """Shared implementation for policy show (and its bare alias)."""
    console.print("\n[bold underline]Command Guardian — Policy Summary[/bold underline]\n")

    console.print("[bold]Supported Intents:[/bold]")
    for intent in classifier.ALL_INTENTS:
        console.print(f"  • {intent}")

    console.print("\n[bold red]Always-Block Rules:[/bold red]")
    for desc in policy.get_block_rules_summary():
        console.print(f"  ✘ {desc}")

    console.print("\n[bold yellow]Risky Intents (require authorization):[/bold yellow]")
    for intent in policy.get_risky_intents():
        console.print(f"  ⚠ {intent}")

    console.print(f"\n[bold]Receipt location:[/bold] {receipts.AUDIT_DIR}\n")


@policy_app.callback(invoke_without_command=True)
def policy_callback(ctx: typer.Context):
    """Show the current policy summary (alias for ``guardian policy show``)."""
    if ctx.invoked_subcommand is None:
        _print_policy_summary()


@policy_app.command("show")
def cmd_policy_show():
    """Print a human-readable policy summary."""
    _print_policy_summary()


# ─────────────────────────── guardian allow ───────────────────────────────


@app.command("allow")
def cmd_allow(
    intent: str = typer.Argument(..., help="Intent to pre-authorize."),
    ttl: int = typer.Option(60, "--ttl", help="Token time-to-live in seconds."),
):
    """Issue a short-lived local allow token for an intent."""
    if intent not in classifier.ALL_INTENTS:
        console.print(f"[red]Unknown intent: {intent}[/red]")
        console.print(f"Valid intents: {', '.join(classifier.ALL_INTENTS)}")
        raise typer.Exit(code=1)

    tok = tokens.issue_token(intent, ttl=ttl)
    console.print(f"\n[bold green]Token issued[/bold green]")
    console.print(f"  token_id     : {tok['token_id']}")
    console.print(f"  intent       : {tok['intent']}")
    console.print(f"  expires_at   : {tok['expires_at']}")
    console.print(f"  decision_hash: {tok['decision_hash'][:32]}…\n")


# ─────────────────────────── guardian verify ──────────────────────────────


@app.command("verify")
def cmd_verify():
    """Verify the audit receipt chain."""
    result = verify.verify_chain()
    if result.ok:
        console.print(f"[bold green]✔ VERIFIED[/bold green]  ({result.total} records)")
    else:
        console.print(f"[bold red]✘ FAILED[/bold red]  at record index {result.failed_index}")
        console.print(f"  Reason: {result.failed_reason}")
        raise typer.Exit(code=1)


# ─────────────────────────── guardian receipts [tail] ─────────────────────

receipts_app = typer.Typer(
    name="receipts",
    help="Audit receipt commands.",
    invoke_without_command=True,
    no_args_is_help=False,
)
app.add_typer(receipts_app, name="receipts", help="Audit receipt commands.")


def _print_receipts(n: int = 20) -> None:
    """Shared implementation for receipts tail (and its bare alias)."""
    recs = receipts.tail_receipts(n)
    if not recs:
        console.print("[dim]No receipts found.[/dim]")
        return

    table = Table(title=f"Last {len(recs)} receipts", show_lines=False, padding=(0, 1))
    table.add_column("ts", style="dim", max_width=25)
    table.add_column("intent", style="cyan")
    table.add_column("decision")
    table.add_column("reason", max_width=50)
    table.add_column("hash", style="dim", max_width=18)

    for r in recs:
        dec_style = "green" if r["decision"] == "ALLOW" else "red"
        table.add_row(
            r["ts"][:19],
            r["intent"],
            f"[{dec_style}]{r['decision']}[/{dec_style}]",
            r["reason"][:50],
            r["hash"][:16] + "…",
        )

    console.print(table)


@receipts_app.callback(invoke_without_command=True)
def receipts_callback(
    ctx: typer.Context,
    n: int = typer.Option(20, "--n", "-n", help="Number of receipts to show."),
):
    """Show recent receipts (alias for ``guardian receipts tail --n N``)."""
    if ctx.invoked_subcommand is None:
        _print_receipts(n)


@receipts_app.command("tail")
def cmd_receipts_tail(
    n: int = typer.Option(20, "--n", "-n", help="Number of receipts to show."),
):
    """Print last N audit receipts."""
    _print_receipts(n)


# ─────────────────────────── entry-point ──────────────────────────────────


def app_entry():
    app()


if __name__ == "__main__":
    app_entry()
