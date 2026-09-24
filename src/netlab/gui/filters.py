"""Display-filter engine shared by every table page.

This is deliberately *not* BPF.  BPF filters are applied by libpcap at
capture time; this filters what is already captured, so an operator can
narrow a view without restarting the capture or losing history.

Syntax:
    plain words        substring match anywhere in the row
    key:value          match one field (ip, src, dst, host, port, proto, ...)
    -term              negate
    terms are ANDed;  "a|b" inside a value ORs alternatives
"""

from __future__ import annotations

from dataclasses import dataclass

FIELD_ALIASES = {
    "ip": ("src", "dst"),
    "addr": ("src", "dst"),
    "host": ("host", "hostname", "sni", "service"),
    "port": ("sport", "dport", "port"),
    "proto": ("proto", "protocol", "app"),
    "protocol": ("proto", "protocol", "app"),
    "src": ("src",),
    "dst": ("dst",),
    "sport": ("sport",),
    "dport": ("dport",),
    "mac": ("mac",),
    "info": ("info",),
    "method": ("method",),
    "status": ("status",),
    "type": ("type", "qtype"),
    "name": ("name", "qname", "hostname"),
    "sni": ("sni",),
    "cipher": ("cipher",),
    "version": ("version",),
    "app": ("app",),
    "state": ("state",),
}


@dataclass(slots=True)
class Term:
    key: str | None
    values: tuple[str, ...]
    negate: bool


class DisplayFilter:
    """A compiled filter. `matches(fields, text)` is the hot path."""

    __slots__ = ("terms", "source", "error")

    def __init__(self, terms: list[Term], source: str, error: str = "") -> None:
        self.terms = terms
        self.source = source
        self.error = error

    @property
    def is_empty(self) -> bool:
        return not self.terms

    def matches(self, fields: dict, text: str) -> bool:
        if not self.terms:
            return True
        low_text = text.lower()
        for term in self.terms:
            hit = False
            if term.key is None:
                hit = any(v in low_text for v in term.values)
            else:
                names = FIELD_ALIASES.get(term.key, (term.key,))
                for name in names:
                    if term.key == 'device':
                        addresses = fields.get('device', (fields.get('src'), fields.get('dst')))
                        hit = any(v in addresses for v in term.values)
                        break
                    raw = fields.get(name)
                    if raw is None:
                        continue
                    cell = str(raw).lower()
                    if any(v in cell for v in term.values):
                        hit = True
                        break
            if hit == term.negate:
                return False
        return True


def _split_terms(text: str) -> list[str]:
    out, buf, quoted = [], [], False
    for ch in text:
        if ch == '"':
            quoted = not quoted
            continue
        if ch.isspace() and not quoted:
            if buf:
                out.append("".join(buf))
                buf = []
            continue
        buf.append(ch)
    if buf:
        out.append("".join(buf))
    return out


def compile_filter(text: str) -> DisplayFilter:
    raw = (text or "").strip()
    if not raw:
        return DisplayFilter([], raw)
    terms: list[Term] = []
    for token in _split_terms(raw):
        negate = False
        if token.startswith("-") and len(token) > 1:
            negate = True
            token = token[1:]
        if ":" in token:
            key, _, value = token.partition(":")
            key = key.strip().lower()
            value = value.strip().lower()
            if key and value:
                terms.append(Term(key, tuple(v for v in value.split("|") if v),
                                  negate))
                continue
        low = token.lower()
        if low:
            terms.append(Term(None, tuple(v for v in low.split("|") if v),
                              negate))
    return DisplayFilter(terms, raw)


FILTER_HELP = (
    "Type to filter the rows already captured. Examples:\n"
    "    10.0.0.5              any field contains this text\n"
    "    ip:10.0.0.5           source or destination address\n"
    "    port:443              source or destination port\n"
    "    proto:tls|http        protocol is TLS or HTTP\n"
    "    host:example.com      hostname / SNI / HTTP Host\n"
    "    -proto:arp            exclude ARP\n"
    "Terms are combined with AND. This is a display filter and does not "
    "change what is being captured - use the BPF filter for that."
)
