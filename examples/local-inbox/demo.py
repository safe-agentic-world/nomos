"""Real Nomos + LangGraph, scripted requests, local SQLite inbox, no LLM/API account."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from nomos_sdk import CustomTool, NomosClient


class LocalGateway:
    """Isolated loopback server and fresh credentials; artifacts stay for inspection."""

    def __init__(self, binary: str, *, ttl: int = 300):
        self.directory = Path(tempfile.mkdtemp(prefix="nomos-inbox-"))
        self.policy = self.directory / "policy.yaml"
        shutil.copyfile(Path(__file__).with_name("policy.yaml"), self.policy)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{port}"
        agent_key, reviewer_key, agent_secret = (secrets.token_hex(24) for _ in range(3))
        config = {
            "gateway": {"listen": f"127.0.0.1:{port}", "transport": "http", "rate_limit_per_minute": 10000},
            "runtime": {"deployment_mode": "unmanaged"},
            "policy": {"policy_bundle_path": str(self.policy)},
            "executor": {"workspace_root": str(self.directory), "sandbox_profile": "local"},
            "audit": {"sink": "sqlite:" + str(self.directory / "audit.db")},
            "approvals": {"enabled": True, "backend": "sqlite", "store_path": str(self.directory / "approvals.db"),
                          "ttl_seconds": ttl, "approver_principals": ["reviewer"]},
            "identity": {"principal": "developer", "agent": "inbox-demo", "environment": "dev",
                         "api_keys": {agent_key: "developer", reviewer_key: "reviewer"},
                         "agent_secrets": {"inbox-demo": agent_secret}},
        }
        config_path = self.directory / "config.json"
        with config_path.open("x", encoding="utf-8") as stream:
            os.chmod(config_path, 0o600)
            json.dump(config, stream)
        self.client = NomosClient(base_url=self.url, bearer_token=agent_key, agent_id="inbox-demo", agent_secret=agent_secret)
        # Never register this reviewer client as an agent tool.
        self.reviewer = NomosClient(base_url=self.url, bearer_token=reviewer_key, agent_id="inbox-demo", agent_secret=agent_secret)
        self.log = (self.directory / "server.log").open("w", encoding="utf-8")
        self.process = subprocess.Popen([binary, "serve", "-c", str(config_path)], stdout=self.log, stderr=self.log)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError(f"Nomos stopped; inspect {self.directory / 'server.log'}")
                try:
                    with urllib.request.urlopen(self.url + "/healthz", timeout=0.3) as response:
                        if response.status == 200:
                            return
                except (OSError, urllib.error.URLError):
                    time.sleep(0.05)
            raise RuntimeError("Nomos did not become ready within 15 seconds")
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def deliver(database: Path, params: dict) -> dict:
    """Local delivery only. A stable message_id deduplicates retries, even on restart."""
    payload = json.dumps(params, sort_keys=True, allow_nan=False)
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS messages (message_id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
        connection.execute("INSERT OR IGNORE INTO messages VALUES (?, ?)", (params["message_id"], payload))
        stored = connection.execute("SELECT payload FROM messages WHERE message_id = ?", (params["message_id"],)).fetchone()[0]
        if stored != payload:
            raise ValueError("message_id already belongs to a different message")
    return {"message_id": params["message_id"], "status": "delivered_to_local_inbox"}


def find_binary(value: str | None) -> str:
    if value:
        candidate = Path(value).resolve()
        if not candidate.is_file():
            raise ValueError(f"Nomos binary not found: {candidate}")
        return str(candidate)
    root = Path(__file__).resolve().parents[2]
    local = root / ("nomos.exe" if os.name == "nt" else "nomos")
    if local.is_file():
        return str(local)
    binary = shutil.which("nomos")
    if not binary:
        raise ValueError("Build first: go build ./cmd/nomos (or pass --nomos /path/to/nomos)")
    return binary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nomos", help="path to the Nomos executable")
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument("--auto-approve", action="store_true", help="scripted approval for CI only")
    choice.add_argument("--reject", action="store_true", help="scripted rejection for CI")
    args = parser.parse_args()
    # The demo never needs network tracing or a model provider.
    os.environ["LANGSMITH_TRACING"] = "false"
    os.environ["LANGCHAIN_TRACING_V2"] = "false"
    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.types import Command
    from nomos_langgraph import tool_graph

    with LocalGateway(find_binary(args.nomos)) as gateway:
        print("Local-only demo: scripted tool requests, real policy checks, no email leaves this machine.")
        print(f"Artifacts: {gateway.directory}")
        resource = lambda p: "inbox://local/messages/" + p["message_id"]
        params = {"message_id": "welcome-1", "recipient": "reader@example.test", "body": "Welcome to Nomos!"}
        draft = CustomTool(client=gateway.client, action_type="email.draft", resource=resource, execute=lambda p: p)
        drafted = draft.invoke(params)
        if not drafted.executed:
            raise RuntimeError("Expected draft to be allowed")
        print("ALLOW: draft prepared")
        sender = CustomTool(client=gateway.client, action_type="email.send", resource=resource,
                            execute=lambda p: deliver(gateway.directory / "inbox.db", p))
        blocked = sender.invoke({**params, "recipient": "blocked@example.net"})
        if blocked.executed or not blocked.is_denied():
            raise RuntimeError("Expected blocked recipient to be denied")
        print("DENY: blocked recipient, delivery did not run")
        graph = tool_graph(sender, checkpointer=InMemorySaver())
        config = {"configurable": {"thread_id": "local-inbox-demo"}}
        pending = graph.invoke({"params": params}, config)
        interruption = pending["__interrupt__"][0].value
        print("REQUIRE_APPROVAL: delivery paused")
        print(json.dumps(interruption, indent=2))
        if args.auto_approve:
            print("CI mode: the demo harness supplies the reviewer approval.")
            approve = True
        elif args.reject:
            approve = False
        else:
            approve = input("Deliver this message to the local inbox? [y/N] ").strip().lower() == "y"
        gateway.reviewer.decide_approval(interruption["approval_id"], "APPROVE" if approve else "DENY")
        completed = graph.invoke(Command(resume=True), config)
        if completed["executed"] != approve:
            raise RuntimeError("Execution did not match the reviewer decision")
        print("DELIVERED: " + json.dumps(completed["value"]) if approve else "REJECTED: delivery did not run")
        print("Inspect inbox.db for delivery and audit.db for authorization/outcome records.")


if __name__ == "__main__":
    main()
