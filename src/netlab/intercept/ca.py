"""The certificate authority that makes SSL MITM possible, and visible.

Intercepting TLS means presenting a certificate for a name we do not own.
There is no way to do that quietly: unless the victim trusts this CA, their
browser says so, loudly, which is the correct behaviour and is left intact.
On an authorised test the operator installs `ca.crt` on the device under test
and the warning stops; nothing here tries to work around a client that has
not been told to trust it.

Leaf certificates are minted on demand per SNI name, cached, and signed by a
CA that is generated once per installation and never leaves the machine.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import ssl
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

CA_COMMON_NAME = "NetLab Interception CA"
CA_ORGANISATION = "NetLab"
CA_VALID_DAYS = 3650
LEAF_VALID_DAYS = 397
MAX_CACHED_LEAVES = 512


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class CertificateAuthority:
    """Generates, stores and uses the interception CA."""

    def __init__(self, directory) -> None:
        self.dir = Path(directory)
        self.key_path = self.dir / "ca.key"
        self.cert_path = self.dir / "ca.crt"
        self.leaf_dir = self.dir / "leaves"
        self._lock = threading.RLock()
        self._key = None
        self._cert = None
        self._contexts: dict[str, ssl.SSLContext] = {}
        self._order: list[str] = []
        self.minted = 0

    # ---------------------------------------------------------------- setup

    @property
    def exists(self) -> bool:
        return self.key_path.is_file() and self.cert_path.is_file()

    def ensure(self, owner_uid: int | None = None) -> "CertificateAuthority":
        """Load the CA, creating it on first use."""
        with self._lock:
            if self._key is not None:
                return self
            self.dir.mkdir(parents=True, exist_ok=True)
            self.leaf_dir.mkdir(parents=True, exist_ok=True)
            if self.exists:
                self._load()
            else:
                self._generate()
            if owner_uid is not None:
                self._chown(owner_uid)
        return self

    def _load(self) -> None:
        self._key = serialization.load_pem_private_key(
            self.key_path.read_bytes(), password=None)
        self._cert = x509.load_pem_x509_certificate(self.cert_path.read_bytes())

    def _generate(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORGANISATION),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                               "Authorised testing only"),
        ])
        now = _utcnow()
        cert = (x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(hours=1))
                .not_valid_after(now + datetime.timedelta(days=CA_VALID_DAYS))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0),
                               critical=True)
                .add_extension(x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False), critical=True)
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                    critical=False)
                .sign(key, hashes.SHA256()))

        self.key_path.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
        os.chmod(self.key_path, 0o600)
        self.cert_path.write_bytes(
            cert.public_bytes(serialization.Encoding.PEM))
        self._key, self._cert = key, cert

    def _chown(self, uid: int) -> None:
        """Hand the CA back to the desktop user when root created it."""
        if os.geteuid() != 0:
            return
        try:
            gid = os.stat(Path.home()).st_gid
        except OSError:
            gid = uid
        for path in (self.dir, self.leaf_dir, self.key_path, self.cert_path):
            try:
                os.chown(path, uid, gid)
            except OSError:
                pass

    # ------------------------------------------------------------ material

    def fingerprint(self) -> str:
        self.ensure()
        digest = self._cert.fingerprint(hashes.SHA256())
        return ":".join("%02X" % b for b in digest)

    def info(self) -> dict:
        self.ensure()
        return {
            "path": str(self.cert_path),
            "subject": CA_COMMON_NAME,
            "fingerprint_sha256": self.fingerprint(),
            "not_after": self._cert.not_valid_after_utc.isoformat(),
            "leaves_minted": self.minted,
        }

    # --------------------------------------------------------------- leaves

    @staticmethod
    def _safe_name(server_name: str) -> str:
        keep = "".join(c if c.isalnum() or c in ".-_" else "_"
                       for c in server_name)
        return keep[:96] or "unknown"

    def leaf_for(self, server_name: str) -> tuple[Path, Path]:
        """Certificate and key paths for `server_name`, minting if needed."""
        self.ensure()
        safe = self._safe_name(server_name)
        cert_path = self.leaf_dir / ("%s.crt" % safe)
        key_path = self.leaf_dir / ("%s.key" % safe)
        with self._lock:
            if cert_path.is_file() and key_path.is_file():
                return cert_path, key_path
            key = ec.generate_private_key(ec.SECP256R1())
            try:
                ip = ipaddress.ip_address(server_name)
                san = [x509.IPAddress(ip)]
                common = server_name
            except ValueError:
                san = [x509.DNSName(server_name)]
                common = server_name
            now = _utcnow()
            cert = (x509.CertificateBuilder()
                    .subject_name(x509.Name([
                        x509.NameAttribute(NameOID.COMMON_NAME, common[:64])]))
                    .issuer_name(self._cert.subject)
                    .public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - datetime.timedelta(hours=1))
                    .not_valid_after(now + datetime.timedelta(days=LEAF_VALID_DAYS))
                    .add_extension(x509.SubjectAlternativeName(san),
                                   critical=False)
                    .add_extension(x509.BasicConstraints(ca=False,
                                                         path_length=None),
                                   critical=True)
                    .add_extension(x509.ExtendedKeyUsage(
                        [x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1")]),
                        critical=False)
                    .add_extension(
                        x509.SubjectKeyIdentifier.from_public_key(
                            key.public_key()), critical=False)
                    # OpenSSL 3 rejects a chain whose leaf cannot name its
                    # issuer, so the authority key id is not optional here.
                    .add_extension(
                        x509.AuthorityKeyIdentifier.from_issuer_public_key(
                            self._cert.public_key()), critical=False)
                    .sign(self._key, hashes.SHA256()))
            key_path.write_bytes(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()))
            os.chmod(key_path, 0o600)
            cert_path.write_bytes(
                cert.public_bytes(serialization.Encoding.PEM)
                + self._cert.public_bytes(serialization.Encoding.PEM))
            self.minted += 1
            return cert_path, key_path

    def context_for(self, server_name: str) -> ssl.SSLContext:
        """A server-side SSL context presenting a certificate for `server_name`."""
        key = (server_name or "").lower() or "localhost"
        with self._lock:
            ctx = self._contexts.get(key)
            if ctx is not None:
                return ctx
        cert_path, key_path = self.leaf_for(key)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert_path), str(key_path))
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except NotImplementedError:              # pragma: no cover
            pass
        with self._lock:
            self._contexts[key] = ctx
            self._order.append(key)
            while len(self._order) > MAX_CACHED_LEAVES:
                self._contexts.pop(self._order.pop(0), None)
        return ctx

    def clear_leaves(self) -> int:
        """Forget every minted leaf. Used when the operator resets the CA."""
        removed = 0
        with self._lock:
            self._contexts.clear()
            self._order.clear()
            if self.leaf_dir.is_dir():
                for path in self.leaf_dir.iterdir():
                    try:
                        path.unlink()
                        removed += 1
                    except OSError:
                        pass
        return removed
