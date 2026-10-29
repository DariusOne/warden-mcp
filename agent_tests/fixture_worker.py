"""Test-only worker: pin the ephemeral certificate in sandboxed Chromium/Edge.

Production worker.py never imports this module or accepts browser test options.
"""
import base64
from pathlib import Path
import sys
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
sys.path.insert(0,str(Path(__file__).resolve().parents[1] / 'agent_worker'))
import worker
from browser_worker import BrowserWorker

if sys.platform.startswith('linux'):
    # The disposable memory-only helper runs as the test user, never root.
    # Production credentials.py still requires UID 0 with no fallback.
    import credentials
    credentials.ROOT_UID = os.getuid()

cert=x509.load_pem_x509_certificate((Path(sys.argv[1])/'test-server.pem').read_bytes())
hasher=hashes.Hash(hashes.SHA256())
hasher.update(cert.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))
pin=base64.b64encode(hasher.finalize()).decode()
worker.BrowserWorker=lambda broker: BrowserWorker(broker,test_options={'headless':True,'launch_args':['--ignore-certificate-errors-spki-list='+pin]})
try: worker.main()
except Exception: sys.exit(1)
