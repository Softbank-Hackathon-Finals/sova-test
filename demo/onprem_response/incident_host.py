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
        ("app_deployment.js", "application/javascript"),
        ("workspace_navigation.js", "application/javascript"),
        ("workspace_navigation.css", "text/css"),
    ):
        host.assets["/__trial/" + name] = (
            Path(__file__).with_name(name).read_bytes(),
            mime,
        )
    # Separate, static-only preview. Never replace the live console or trial routes.
    preview = Path(__file__).resolve().parents[1] / "response_scenarios"
    for name, mime in (
        ("index.html", "text/html; charset=utf-8"),
        ("model.mjs", "text/javascript"),
        ("motion.mjs", "text/javascript"),
        ("layout.mjs", "text/javascript"),
        ("commands.mjs", "text/javascript"),
        ("injection_console.mjs", "text/javascript"),
        ("view.mjs", "text/javascript"),
        ("styles.css", "text/css"),
    ):
        host.assets["/__mock/response/" + name] = ((preview / name).read_bytes(), mime)
    host.assets["/__mock/response/"] = host.assets["/__mock/response/index.html"]
    host.assets["/__mock/response/base.css"] = (
        (preview.parents[1] / "console" / "src" / "styles.css").read_bytes(),
        "text/css",
    )
    return host
