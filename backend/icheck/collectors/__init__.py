"""Built-in collector adapters.

Adapters translate source-specific data into iCheck collection envelopes. They
do not write to the database or receive raw infrastructure credentials.
"""

from .http_json import collect_http_json
from .psrp_cim import collect_psrp_cim
from .snmp_exporter import collect_snmp_exporter
from .windows_exporter import collect_windows_exporter

__all__ = [
    "collect_http_json",
    "collect_psrp_cim",
    "collect_snmp_exporter",
    "collect_windows_exporter",
]
