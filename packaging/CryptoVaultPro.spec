# -*- mode: python ; coding: utf-8 -*-
"""Reproducible Windows build for CryptoVault Pro.

The Codex build runtime also contains Poppler's generic ICU 78 libraries on
PATH. Qt intentionally uses the Windows system ICU. If PyInstaller resolves
and bundles Poppler's copies, they shadow System32 and QtCore fails to load.
"""

from PyInstaller.utils.hooks import collect_all

datas = []
binaries = []
hiddenimports = []

for package in ("argon2", "blake3"):
    package_data, package_binaries, package_hidden = collect_all(package)
    datas += package_data
    binaries += package_binaries
    hiddenimports += package_hidden

analysis = Analysis(
    ["../cryptovault/app.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

# Never ship the Poppler ICU copies accidentally discovered via PATH. QtCore
# imports the Windows ICU ABI exposed by C:\Windows\System32\icuuc.dll.
conflicting_icu = {"icuuc.dll", "icudt78.dll"}
analysis.binaries = [entry for entry in analysis.binaries if entry[0].lower() not in conflicting_icu]

archive = PYZ(analysis.pure)

executable = EXE(
    archive,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="CryptoVaultPro",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
