# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

import os

extra_datas = [('../app/static', 'app/static')]
if os.path.exists('../traffic_classifier.pkl'):
    extra_datas.append(('../traffic_classifier.pkl', '.'))

a = Analysis(
    ['../main.py'],
    pathex=['..'],
    binaries=[],
    datas=extra_datas,
    hiddenimports=[
        'uvicorn.logging',
        'uvicorn.loops',
        'uvicorn.loops.auto',
        'uvicorn.protocols',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan',
        'uvicorn.lifespan.on',
        'fastapi',
        'websockets',
        'pydantic',
        'scapy',
        'scapy.layers.inet',
        'scapy.layers.l2',
        'sklearn',
        'sklearn.ensemble',
        'joblib',
        'multipart',
        'python_multipart',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='CryptoFlow-IDS',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True, # Keeps console visible for sniffing logs and admin elevation
    uac_admin=True, # Enforce Windows UAC Administrator elevation manifest
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='CryptoFlow-IDS',
)
