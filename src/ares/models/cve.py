from dataclasses import dataclass


@dataclass
class CVE:
    created_at: str
    updated_at: str
    cve_id: str
    description: str
