__version__ = "1.1.0"

__all__ = [
    "scan_domain",
    "scan_ip",
    "__version__",
]

from .scan import scan_domain, scan_ip
