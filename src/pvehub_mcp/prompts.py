"""MCP prompts for common operational workflows."""

from __future__ import annotations

from typing import Any


def register(hub: Any) -> None:
    mcp = hub.mcp

    @mcp.prompt(name="health_check", description="Review PVE/PBS health and report anomalies")
    def health_check() -> str:
        return (
            "Check the Proxmox environment health. Steps: 1) call pvehub_capabilities to see "
            "which tools and token privileges are available; 2) list nodes and guests; "
            "3) inspect node status and storage usage; 4) list running and failed tasks; "
            "5) list PBS datastores, GC status and recent failed tasks. Report only real "
            "findings with the tool data as evidence, and separate warnings from blockers."
        )

    @mcp.prompt(name="provision_lxc", description="Plan and create a new LXC container")
    def provision_lxc(hostname: str, storage: str, vmid: int | None = None) -> str:
        target = f"vmid {vmid}" if vmid else "the next free vmid"
        return (
            f"Provision an LXC container with hostname {hostname!r} on storage {storage!r} "
            f"using {target}. First list nodes, storage and templates, then propose a resource "
            "plan (cores, memory, disk). Only call pve_guest_create_lxc with confirm=true after "
            "the plan is explicit. After creation, verify the task log and report the result."
        )

    @mcp.prompt(name="backup_audit", description="Audit PBS backup coverage, retention and verification")
    def backup_audit() -> str:
        return (
            "Audit the PBS backup posture. Steps: 1) list datastores and namespaces; "
            "2) list snapshots per datastore, grouped by backup type and id; 3) check GC and "
            "verify job status; 4) list failed tasks; 5) compare the newest snapshot per guest "
            "with its expected backup schedule. Report gaps (missing, stale, unverified) and "
            "never run prune, forget or GC without explicit confirmation."
        )
