"""Opt-in composition with the existing team's qualified local trial host.

The caller authenticates the OS-owner session and pins the platform host source.
No native T10 route, role or approval is created by this composition.
"""

from pathlib import Path

from .incident_supervisor import IncidentSupervisor


def compose(console, manager, *, authorize, terminal_command, host_factory):
    if not isinstance(manager, IncidentSupervisor) or not callable(host_factory):
        raise ValueError("registered_incident_supervisor_and_host_required")
    host = host_factory(
        console, manager, authorize=authorize, terminal_command=terminal_command
    )
    host.assets["/__trial/client.js"] = (
        Path(__file__).with_name("incident_client.js").read_bytes(),
        "application/javascript",
    )
    for name, mime in (
        ("migration_view.js", "application/javascript"),
        ("workspace_navigation.js", "application/javascript"),
        ("workspace_navigation.css", "text/css"),
    ):
        host.assets["/__trial/" + name] = (
            Path(__file__).with_name(name).read_bytes(),
            mime,
        )
    return host
