"""Operator-selected built web bundle; HTTP paths never become filesystem paths."""

from pathlib import Path

from sova.domain.contracts import ContractError


class ConsoleWebBundle:
    def __init__(self, root):
        root = Path(root).resolve(strict=True)
        if (
            not root.is_dir()
            or (root / "index.html").is_symlink()
            or not (root / "index.html").is_file()
        ):
            raise ContractError("Built console index required")
        if (root / "index.html").stat().st_size > 131072:
            raise ContractError("Bounded built console index required")
        index = (root / "index.html").read_bytes()
        self.assets = {
            "/": (index, "text/html; charset=utf-8"),
            "/console": (index, "text/html; charset=utf-8"),
            "/console/": (index, "text/html; charset=utf-8"),
        }
        kinds = {
            ".js": "text/javascript",
            ".css": "text/css",
            ".svg": "image/svg+xml",
            ".woff2": "font/woff2",
        }
        assets = root / "assets"
        if not assets.is_dir() or assets.is_symlink():
            raise ContractError("Built console assets required")
        paths = list(assets.iterdir())
        if not 1 <= len(paths) <= 64:
            raise ContractError("Bounded web asset set required")
        for path in paths:
            if path.is_symlink() or not path.is_file() or path.suffix not in kinds:
                raise ContractError("Only fixed public build assets accepted")
            if path.stat().st_size > 4 * 1024 * 1024:
                raise ContractError("Bounded web asset required")
            data = path.read_bytes()
            self.assets["/console/assets/" + path.name] = (data, kinds[path.suffix])

    def get(self, path):
        return self.assets.get(path)
