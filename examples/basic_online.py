# -*- coding: utf-8 -*-
from netmiko import ConnectHandler
from rich import print

from auditor.configauditor import CiscoConfigAuditor

devices = [
    {
        "device_type": "cisco_ios",
        "ip": "devnetsandboxiosxe.cisco.com",
        "username": "admin",
        "password": "C1sco12345",
    }
]

for device in devices:
    print(f"Trying {device.get('ip')}...", end="\r")
    with ConnectHandler(**device) as conn:
        print(f"Connected to {conn.host}:{conn.port}")
        if not conn.check_enable_mode():
            conn.enable()
            conn.disable_paging()
        print("Parsing 'show running-config full', please wait...", end="\r")
        config = conn.send_command(command_string="show running-config full")
        hostname = conn.find_prompt()[:-1]
        print(f"Parsed 'show running-config full' from {conn.host} ({hostname})")
    print(f"Disconnected from {conn.host}")

    # Create audit instance
    audit = CiscoConfigAuditor()
    # Global Audit
    audit.global_config(config)
    # Interace-Level Audit
    audit.interface_config(config)
    # Print audit result in table
    audit.get_report()
