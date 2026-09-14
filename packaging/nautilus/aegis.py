"""Nautilus (GNOME Files) right-click integration for Aegis.

Mirrors packaging/aegis.desktop (the Dolphin/KIO service menu): same five
actions, same aegis CLI flags. Requires python3-nautilus (gir1.2-nautilus-3.0)
on the target machine; harmless no-op everywhere else.
"""

import subprocess

import gi

gi.require_version("Nautilus", "3.0")
from gi.repository import GObject, Nautilus  # noqa: E402

ACTIONS = [
    ("Encrypt (for me)", ["encrypt"]),
    ("Encrypt with a photo", ["encrypt", "--photo"]),
    ("Encrypt to share", ["encrypt", "--ask"]),
    ("Decrypt", ["decrypt"]),
    ("Show header info", ["info"]),
]


class AegisMenuProvider(GObject.GObject, Nautilus.MenuProvider):
    def _launch(self, args, path):
        def handler(_menu_item):
            subprocess.Popen(["aegis", "--gui", *args, path])

        return handler

    def get_file_items(self, *call_args):
        files = call_args[-1]
        if len(files) != 1:
            return []
        target = files[0]
        if target.get_uri_scheme() != "file":
            return []
        path = target.get_location().get_path()
        if path is None:
            return []

        top = Nautilus.MenuItem(
            name="AegisMenuProvider::Aegis",
            label="Aegis",
            icon="document-encrypt",
        )
        submenu = Nautilus.Menu()
        top.set_submenu(submenu)

        for label, args in ACTIONS:
            item = Nautilus.MenuItem(
                name=f"AegisMenuProvider::{label}",
                label=label,
            )
            item.connect("activate", self._launch(args, path))
            submenu.append_item(item)

        return [top]
