# -*- coding: utf-8 -*-
from pathlib import Path

from ciscoconfaudit import CiscoConfAudit

# Read config file
run_cfg = Path("config-sample.txt").read_text(encoding="utf-8")

# Create audit instance
audit = CiscoConfAudit()

# Global Audit
audit.global_config(run_cfg)

# Interace-Level Audit
audit.interface_config(run_cfg)

# Print audit result
audit.get_report()
