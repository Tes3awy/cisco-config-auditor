# -*- coding: utf-8 -*-
import pathlib

from auditor.configauditor import CiscoConfigAuditor

# Read config file
run_cfg = pathlib.Path("config.txt").read_text(encoding="utf-8")

# Create audit instance
audit = CiscoConfigAuditor()

# Global Audit
audit.global_config(run_cfg)

# Interace-Level Audit
audit.interface_config(run_cfg)

# Print audit result
audit.get_report()
