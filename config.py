from enum import Enum


class Severity(str, Enum):
    CRITICAL = "Critical"   # Equivalent to Material Weakness (SOX)
    HIGH = "High"           # Equivalent to Significant Deficiency (SOX)
    MEDIUM = "Medium"       # Control Deficiency
    LOW = "Low"             # Observation / Minor Gap


class IssueType(str, Enum):
    CONTROL_DEFICIENCY = "Control Deficiency"
    SELF_IDENTIFIED_ISSUE = "Self-Identified Issue"
    AUDIT_FINDING = "Audit Finding"
    REGULATORY_FINDING = "Regulatory Finding"
    INCIDENT_DERIVED = "Incident-Derived Issue"
    VULNERABILITY = "Vulnerability"
    PROCESS_GAP = "Process Gap"


class ControlDomain(str, Enum):
    ACCESS_MANAGEMENT = "Access Management"
    CHANGE_MANAGEMENT = "Change Management"
    IT_OPERATIONS = "IT Operations"
    INFORMATION_SECURITY = "Information Security"
    DATA_MANAGEMENT = "Data Management"
    VENDOR_MANAGEMENT = "Vendor Management"
    BUSINESS_CONTINUITY = "Business Continuity & DR"
    SOFTWARE_DEVELOPMENT = "Software Development"
    INFRASTRUCTURE = "Infrastructure & Networks"
    INCIDENT_MANAGEMENT = "Incident Management"


class Status(str, Enum):
    OPEN = "Open"
    IN_REMEDIATION = "In Remediation"
    PENDING_VALIDATION = "Pending Validation"
    CLOSED = "Closed"
    ESCALATED = "Escalated"
    OVERDUE = "Overdue"
    ACCEPTED_RISK = "Accepted Risk"


# Remediation SLA in calendar days, by severity
SLA_DAYS: dict[str, int] = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 60,
    Severity.MEDIUM: 90,
    Severity.LOW: 180,
}

# First-line teams and the control domains they own
FIRST_LINE_TEAMS: dict[str, list[str]] = {
    "Infrastructure Services": [
        ControlDomain.INFRASTRUCTURE,
        ControlDomain.IT_OPERATIONS,
        ControlDomain.INCIDENT_MANAGEMENT,
    ],
    "Application Development": [
        ControlDomain.SOFTWARE_DEVELOPMENT,
        ControlDomain.CHANGE_MANAGEMENT,
    ],
    "Service Continuity & Disaster Recovery": [
        ControlDomain.BUSINESS_CONTINUITY,
    ],
    "Information Security": [
        ControlDomain.INFORMATION_SECURITY,
        ControlDomain.ACCESS_MANAGEMENT,
        ControlDomain.DATA_MANAGEMENT,
    ],
    "Third Party Risk Management": [
        ControlDomain.VENDOR_MANAGEMENT,
    ],
}

# Reverse lookup: domain → primary first-line team
DOMAIN_TO_TEAM: dict[str, str] = {
    domain.value: team
    for team, domains in FIRST_LINE_TEAMS.items()
    for domain in domains
}

# Framework references per control domain
FRAMEWORK_REFERENCES: dict[str, dict[str, str]] = {
    ControlDomain.ACCESS_MANAGEMENT: {
        "SOX_ITGC": "Access to Programs and Data",
        "COBIT": "DSS05.04 - Manage User and Access Rights",
        "ISO_27001": "A.9 - Access Control",
        "NIST_CSF": "PR.AC - Identity Management and Access Control",
    },
    ControlDomain.CHANGE_MANAGEMENT: {
        "SOX_ITGC": "Program Changes",
        "COBIT": "BAI06 - Manage IT Changes",
        "ISO_27001": "A.12.1.2 - Change Management",
        "NIST_CSF": "PR.IP-3 - Configuration Change Control",
    },
    ControlDomain.IT_OPERATIONS: {
        "SOX_ITGC": "Computer Operations",
        "COBIT": "DSS01 - Manage Operations",
        "ISO_27001": "A.12 - Operations Security",
        "NIST_CSF": "PR.IP - Information Protection Processes",
    },
    ControlDomain.INFORMATION_SECURITY: {
        "SOX_ITGC": "Computer Operations",
        "COBIT": "DSS05 - Manage Security Services",
        "ISO_27001": "A.6 to A.18 (multiple domains)",
        "NIST_CSF": "All five Functions",
    },
    ControlDomain.DATA_MANAGEMENT: {
        "SOX_ITGC": "Access to Programs and Data",
        "COBIT": "DSS06 - Manage Business Process Controls",
        "ISO_27001": "A.8 - Asset Management",
        "NIST_CSF": "PR.DS - Data Security",
    },
    ControlDomain.VENDOR_MANAGEMENT: {
        "SOX_ITGC": "Third-Party / Service Organization",
        "COBIT": "APO10 - Manage Vendors",
        "ISO_27001": "A.15 - Supplier Relationships",
        "NIST_CSF": "ID.SC - Supply Chain Risk Management",
    },
    ControlDomain.BUSINESS_CONTINUITY: {
        "SOX_ITGC": "Computer Operations",
        "COBIT": "DSS04 - Manage Continuity",
        "ISO_27001": "A.17 - Information Security Aspects of BCM",
        "NIST_CSF": "RC - Recover",
    },
    ControlDomain.SOFTWARE_DEVELOPMENT: {
        "SOX_ITGC": "Program Development",
        "COBIT": "BAI03 - Manage Solutions Identification and Build",
        "ISO_27001": "A.14 - System Acquisition, Development and Maintenance",
        "NIST_CSF": "PR.IP-2 - System Development Life Cycle",
    },
    ControlDomain.INFRASTRUCTURE: {
        "SOX_ITGC": "Computer Operations",
        "COBIT": "BAI09 - Manage Assets",
        "ISO_27001": "A.11 Physical / A.12 Operations Security",
        "NIST_CSF": "PR.PT - Protective Technology",
    },
    ControlDomain.INCIDENT_MANAGEMENT: {
        "SOX_ITGC": "Computer Operations",
        "COBIT": "DSS02 - Manage Service Requests and Incidents",
        "ISO_27001": "A.16 - Information Security Incident Management",
        "NIST_CSF": "RS - Respond",
    },
}
