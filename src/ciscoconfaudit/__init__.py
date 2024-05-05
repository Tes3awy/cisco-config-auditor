# -*- coding: utf-8 -*-
from ciscoconfparse import CiscoConfParse
from rich.console import Console
from rich.table import Table

__version__ = "0.2.0"
__all__ = ["ciscoconfaudit"]
PY_MAJ_VER = 3
PY_MIN_VER = 8
MIN_PYTHON_VER = "3.8"

FAIL = "[bold red]:heavy_multiplication_x: FAIL[/bold red]"
PASS = "[bold green]:heavy_check_mark: PASS[/bold green]"
RECOMMENDED = "[bold blue]RECOMMENDED[/bold blue]"
WARN = "[bold yellow]WARN[/bold yellow]"
NOT_IN_USE = "[bold white]NOT IN USE[/bold white]"
UNAVAILABLE = "[bold white]UNAVAILABLE[/bold white]"
ACC_INTF_VERIFY = "([yellow]Check access ports configuration[/yellow])"
L3_INTF_VERIFY = "([yellow]Verify L3 interfaces configuration[/yellow])"
IS_ACCESS_PORT = r"^\sswitchport\smode\saccess$"


class CiscoConfAudit(object):
    def __init__(self, global_table=None, interface_table=None, parse=None):
        self.console = Console(record=True, tab_size=4)
        self.global_table: Table = global_table
        self.interface_table: Table = interface_table
        self.parse: CiscoConfParse = parse

    def create_table(self, title: str) -> Table:
        table = Table(
            show_header=True,
            show_edge=True,
            show_lines=False,
            expand=True,
            highlight=True,
            caption=f"End of {title}",
            title=f"[bold magenta]{title}[/bold magenta]",
        )
        table.add_column(header="Audit", no_wrap=True)
        table.add_column(header="Status", no_wrap=True)
        return table

    # Configuration Checks
    def check_service(self, pattern: str, cmd: str):
        if self.parse.find_lines(pattern):
            self.global_table.add_row(cmd, FAIL)
        else:
            self.global_table.add_row(cmd, PASS)

    def check_config(self, pattern: str, cmd: str):
        if self.parse.find_lines(pattern):
            self.global_table.add_row(cmd, PASS)
        else:
            self.global_table.add_row(cmd, FAIL)

    def check_vuln_config(self, pattern: str, cmd: str):
        if not self.parse.find_lines(pattern):
            self.global_table.add_row(cmd, NOT_IN_USE)
        elif self.parse.find_lines(pattern):
            self.global_table.add_row(cmd, WARN)
        else:
            self.global_table.add_row(cmd, PASS)

    def check_optional_config(self, pattern: str, cmd: str):
        if self.parse.find_lines(pattern):
            self.global_table.add_row(cmd, PASS)
        else:
            self.global_table.add_row(cmd, RECOMMENDED)

    # Global Config Audit
    def global_config(self, running_config: str):
        # Parse configuration
        self.parse = CiscoConfParse(
            running_config.splitlines(), syntax="ios", factory=True, read_only=True
        )
        hostname = self.parse.re_match_iter_typed(
            r"^hostname\s+(\S+)", default="Device"
        )
        self.global_table = self.create_table(f"{hostname} Global Config Audit")
        # Perform checks and populate the table
        self.check_service(
            r"^service\stcp-small-servers$", "no service tcp-small-servers"
        )
        self.check_service(
            r"^service\sudp-small-servers$", "no service udp-small-servers"
        )
        self.check_service(r"^no\sip\sfinger$", "no ip finger")
        self.check_service(r"^no\sservice\sfinger$", "no service finger")
        self.check_service(r"^no\sip\sbootp\sserver$", "no ip bootp server")
        self.check_config(r"^ip\sdhcp\sbootp\signore$", "ip dhcp bootp ignore")
        self.check_config(
            r"^no\sip\sdomain-lookup$|^no\sip\sdomain\slookup$",
            "no ip domain-lookup | no ip domain lookup",
        )
        self.check_config(
            r"^ip\sdomain\sname\s\w+$|^ip\sdomain-name\s\w+$",
            "ip domain name <domain> | ip domain-name <domain>",
        )
        self.check_service(r"^no\sservice\spad$", "no service pad")
        self.check_config(r"^no\sip\shttp\sserver$", "no ip http server")
        self.check_config(r"^no\sip\shttp\ssecure-server$", "no ip http secure-server")
        self.check_service(r"^no\sservice\sconfig$", "no service config")
        self.check_config(
            r"^no\sservice\spassword-recovery$",
            "no service password-recovery (Use with caution)",
        )
        self.check_service(r"^service\scall-home$", "no service call-home")
        self.check_service(
            r"^service\spassword-encryption$", "service password-encryption"
        )
        self.check_config(
            r"^service\stimestamps\slog\sdatetime\smsec\slocaltime\sshow-timezone\syear$",
            "service timestamps log datetime msec localtime show-timezone year",
        )
        self.check_config(
            r"^service\stimestamps\sdebug\sdatetime\smsec\slocaltime\sshow-timezone\syear$",
            "service timestamps debug datetime msec localtime show-timezone year",
        )
        self.check_config(r"^service\stcp-keepalives-in$", "service tcp-keepalives-in")
        self.check_config(
            r"^service\stcp-keepalives-out$", "service tcp-keepalives-out"
        )
        self.check_config(
            r"^configuration\smode\sexclusive\sauto$",
            "configuration mode exclusive auto",
        )
        self.check_config(r"^secure\sboot-image$", "secure boot-image")
        self.check_config(r"^secure\sboot-config\W$", "secure boot-config")
        self.check_config(r"^banner\smotd", "banner motd")
        self.check_config(r"^udld\senable$", "udld enable")
        self.check_config(r"^ip\sdhcp\ssnooping$", "ip dhcp snooping")
        self.check_config(
            r"^ip\sdhcp\ssnooping\svlan\s\d+(?:,\d+)*$",
            "ip dhcp snooping vlan <vlan-range>",
        )
        self.check_config(
            r"^ip\sarp\sinspection\svlan\s\d+(?:,\d+)*$",
            "ip arp inspection vlan <vlan-range>",
        )
        self.check_config(
            r"^ip\sdhcp\ssnooping\sinformation\soption$",
            "ip dhcp snooping information option",
        )
        self.check_config(r"^ip\sssh\sversion\s2$", "ip ssh version 2")
        self.check_config(r"^ip\sssh\stime-out\s60$", "ip ssh time-out 60")
        self.check_config(
            r"^ip\sssh\sauthentication-retries\s3$", "ip ssh authentication-retries 3"
        )
        self.check_config(
            r"^ip\sssh\sdh\smin\ssize\s(2048|4096)$", "ip ssh dh min size 2048|4096"
        )
        self.check_optional_config(
            r"^ip\sssh\sserver\salgorithm\sencryption\saes\d{3}-ctr\saes\d{3}-ctr\saes\d{3}-ctr$",
            "ip ssh server algorithm encryption aes128-ctr aes192-ctr aes256-ctr",
        )
        self.check_optional_config(
            r"^ip\sssh\sclient\salgorithm\sencryption\saes\d{3}-ctr\saes\d{3}-ctr\saes\d{3}-ctr$",
            "ip ssh client algorithm encryption aes128-ctr aes192-ctr aes256-ctr",
        )
        self.check_config(r"^no\sip\ssource-route$", "no ip source-route")
        self.check_config(r"^no\sipv6\ssource-route$", "no ipv6 source-route")
        self.check_config(
            r"^no\sip\sgratuitous-arps$|^no\sip\sarp\sgratuitous$",
            "no ip gratuitous-arps | no ip arp gratuitous",
        )
        self.check_config(r"^ip\soptions\sdrop$", "ip options drop")
        self.check_config(r"^no\svstack$", "no vstack")
        self.check_config(r"^no\slogging\sconsole$", "no logging console")
        self.check_config(r"^no\slogging\smonitor$", "no logging monitor")
        self.check_config(
            r"^memory\sfree\slow-watermark\sprocessor\s\d{1,7}$",
            "memory free low-watermark processor <threshold>",
        )
        self.check_config(
            r"^memory\sfree\slow-watermark\sio\s\d{1,7}$",
            "memory free low-watermark io <threshold>",
        )
        self.check_config(
            r"^memory\sreserve\scritical\s\d{1,10}$", "memory reserve critical <value>"
        )
        self.check_optional_config(
            r"^exception\scrashinfo\smaximum\sfiles\s\d+$",
            "exception crashinfo maximum files <number-of-files>",
        )
        self.check_optional_config(
            r"^vtp\smode\s(transparent|off)$", "vtp mode transparent|off"
        )
        self.check_optional_config(
            r"^no\ssystem\signore\sstartupconfig\sswitch\sall$",
            "no system ignore startupconfig switch all",
        )
        self.check_optional_config(
            r"^diagnostic\sbootup\slevel\sminimal$", "diagnostic bootup level minimal"
        )
        self.check_optional_config(
            r"^software\sauto-upgrade\senable$", "software auto-upgrade enable"
        )
        self.check_optional_config(
            r"^license\ssmart\stransport\soff$", "license smart transport off"
        )
        self.check_optional_config(r"^login\son-success\slog$", "login on-success log")
        self.check_optional_config(r"^login\son-failure\slog$", "login on-failure log")
        self.check_optional_config(
            r"^clock\stimezone\s\w{3,4}\s-?\d{1,2}\s-?\d{1,2}$",
            "clock timezone <timezone> <hours_offset> <mintues_offset>",
        )
        self.check_config(r"^ntp\sserver\s\d", "ntp server")
        # IOS and IOS-XE versions only
        self.check_config(
            r"^no\sntp\sallow\smode\scontrol\s0$", "no ntp allow mode control 0"
        )
        self.check_config(
            r"^username\s\w+\sprivilege\s\d{1,2}\ssecret\s[8-9]\s",
            "username <username> privilege <priv_level> secret [8-9] <password>",
        )
        self.check_config(
            r"^enable\salgorithm-type\sscrypt\ssecret\s",
            "enable algorithm-type scrypt secret <password>",
        )
        # Check for AAA settings
        if self.parse.find_lines(r"^no\saaa\snew-model$"):
            self.global_table.add_row("aaa new-model", FAIL)
        else:
            self.global_table.add_row("aaa new-model", PASS)
            # Authentication
            self.check_config(
                r"^aaa\sauthentication\slogin\sdefault\sgroup\stacacs\+\senable$",
                "aaa authentication login default group tacacs+ enable",
            )
            self.check_config(
                r"^aaa\sauthentication\sattempts\slogin\s\d+$",
                "aaa authentication attempts login <max-attempts>",
            )
            # Authorization
            self.check_config(
                r"^aaa\sauthorization\sexec\sdefault\sgroup\stacacs\snone$",
                "aaa authorization exec default group tacacs none",
            )
            self.check_config(
                r"^aaa\sauthorization\scommands\s0\sdefault\sgroup\stacacs\snone$",
                "aaa authorization commands 0 default group tacacs none",
            )
            self.check_config(
                r"^aaa\sauthorization\scommands\s1\sdefault\sgroup\stacacs\snone$",
                "aaa authorization commands 1 default group tacacs none",
            )
            self.check_config(
                r"aaa\sauthorization\scommands\s15\sdefault\sgroup\stacacs\snone",
                "aaa authorization commands 15 default group tacacs none",
            )
            # Accounting
            self.check_config(
                r"^aaa\saccounting\sexec\sdefault\sstart-stop\sgroup\stacacs$",
                "aaa accounting exec default start-stop group tacacs",
            )
            self.check_config(
                r"^aaa\saccounting\scommands\s0\sdefault\sstart-stop\sgroup\stacacs$",
                "aaa accounting commands 0 default start-stop group tacacs",
            )
            self.check_config(
                r"^aaa\saccounting\scommands\s0\sdefault\sstart-stop\sgroup\stacacs$",
                "aaa accounting commands 0 default start-stop group tacacs",
            )
            self.check_config(
                r"^aaa\saccounting\scommands\s15\sdefault\sstart-stop\sgroup\stacacs",
                "aaa accounting commands 15 default start-stop group tacacs",
            )

        # Check for weak SNMPv2c community strings
        self.check_vuln_config(
            r"^snmp-server\scommunity\sprivate\srw$|^snmp-server\scommunity\spublic\sro$",
            "Weak SNMPv2c community string (Trivial authentication)",
        )

    # Interface-Level Audit
    def interface_config(self, running_config: str):
        self.parse = CiscoConfParse(
            running_config.splitlines(), syntax="ios", factory=True
        )
        hostname = self.parse.re_match_iter_typed(
            r"^hostname\s+(\S+)", default="Device"
        )
        self.interface_table = self.create_table(f"{hostname} Interface-Level Audit")
        self.check_vlan1(self.parse)
        self.check_mop(self.parse)
        self.check_port_security(self.parse)
        self.check_stp_portfast(self.parse)
        self.check_stp_bpdu(self.parse)
        self.check_stp_root(self.parse)
        self.check_cdp(self.parse)
        self.check_lldp(self.parse)
        self.check_ip_src_verify(self.parse)
        self.check_sticky_mac(self.parse)
        self.check_arp_proxy(self.parse)
        self.check_ip_redirects(self.parse)
        self.check_ip_unreachables(self.parse)
        self.check_directed_broadcast(self.parse)
        self.check_lines(self.parse)

    def check_vlan1(self, parse: CiscoConfParse):
        # sourcery skip: use-named-expression
        vlan1_intf = parse.find_objects(linespec=r"^interface\s[vV]lan1$")
        if not vlan1_intf:
            self.interface_table.add_row(
                "'interface Vlan1'", "[bold white]NOT FOUND[/bold white]"
            )
        else:
            msg = "'{0:s}' has no ip address and is shutdown"
            for vlan1_obj in vlan1_intf:
                if vlan1_obj.has_child_with(
                    r"\sshutdown$"
                ) and vlan1_obj.has_child_with(r"\sno\sip\saddress$"):
                    self.interface_table.add_row(msg.format(vlan1_obj.text), PASS)
                else:
                    self.interface_table.add_row(msg.format(vlan1_obj.text), FAIL)

    def check_mop(self, parse: CiscoConfParse):
        mop_intfs_total, mop_intfs_success = 0, 0
        cdp_intfs = parse.find_objects_w_child(
            parentspec=r"^interface\s", childspec=IS_ACCESS_PORT
        )
        for cdp_obj in cdp_intfs:
            if not cdp_obj.re_search_children(
                r"^\sno\smop\senabled$"
            ) and not cdp_obj.re_search_children(r"^\s+shutdown$"):
                self.interface_table.add_row(f"{cdp_obj.text} no mop enabled", FAIL)
            else:
                mop_intfs_success += 1
            mop_intfs_total += 1
        try:
            if mop_intfs_success / mop_intfs_total == 1:
                self.interface_table.add_row(
                    "no mop enabled (All access interfaces)", PASS
                )
        except ZeroDivisionError:
            self.interface_table.add_row(f"no mop enabled {ACC_INTF_VERIFY}", WARN)

    def check_port_security(self, parse: CiscoConfParse):
        ps_intfs_total, ps_intfs_pass = 0, 0
        ps_intfs = parse.find_objects_w_child(
            parentspec=r"^interface\s", childspec=IS_ACCESS_PORT
        )
        for ps_obj in ps_intfs:
            if (
                not ps_obj.re_search_children(
                    r"^\sswitchport\sport-security|^\sip\sverify\ssource\sport\ssecurity$"
                )
                and not ps_obj.re_search_children(
                    r"^\sswitchport\sport-security\smac-address\s"
                )
                and not ps_obj.re_search_children(r"^\s+shutdown$")
            ):
                self.interface_table.add_row(
                    f"{ps_obj.text} switchport port-security mac-address", FAIL
                )
            else:
                ps_intfs_pass += 1
            ps_intfs_total += 1
        try:
            if ps_intfs_pass / ps_intfs_total == 1:
                self.interface_table.add_row(
                    "switchport port-security (All access interfaces)", PASS
                )
        except ZeroDivisionError:
            self.interface_table.add_row(
                f"switchport port-security {ACC_INTF_VERIFY}", WARN
            )

    def check_stp_portfast(self, parse: CiscoConfParse):
        if not bool(parse.find_objects(r"^spanning-tree\sportfast\sdefault$")):
            stp_intfs_total, stp_intfs_pass = 0, 0
            stp_intfs = parse.find_objects_w_child(
                parentspec=r"^interface\s", childspec=IS_ACCESS_PORT
            )
            for stp_obj in stp_intfs:
                if not stp_obj.re_search_children(
                    r"^\sspanning-tree\sportfast\s\w+"
                ) and not stp_obj.re_search_children(r"^\s+shutdown$"):
                    self.interface_table.add_row(
                        f"{stp_obj.text} spanning-tree portfast", FAIL
                    )
                else:
                    stp_intfs_pass += 1
                stp_intfs_total += 1
            try:
                if stp_intfs_pass / stp_intfs_total == 1:
                    self.interface_table.add_row(
                        "spanning-tree portfast (All access interfaces)", PASS
                    )
            except ZeroDivisionError:
                self.interface_table.add_row(
                    f"spanning-tree portfast {ACC_INTF_VERIFY}", WARN
                )
        else:
            self.interface_table.add_row(
                "spanning-tree portfast default ([cyan]Global[/cyan])",
                PASS,
            )

    def check_stp_bpdu(self, parse: CiscoConfParse):
        if not bool(
            parse.find_objects(r"^spanning-tree\sportfast\sbpduguard\sdefault$")
        ):
            bpdu_intfs_total, bpdu_intfs_pass = 0, 0
            bpdu_intfs = parse.find_objects_w_child(
                parentspec=r"^interf", childspec=IS_ACCESS_PORT
            )
            for bpdu_obj in bpdu_intfs:
                if not bpdu_obj.re_search_children(
                    r"^\sspanning-tree\sbpduguard\senable$"
                ) and not bpdu_obj.re_search_children(r"^\s+shutdown$"):
                    self.interface_table.add_row(
                        f"{bpdu_obj.text} spanning-tree bpduguard enable", FAIL
                    )
                else:
                    bpdu_intfs_pass += 1
                bpdu_intfs_total += 1
            try:
                if bpdu_intfs_pass / bpdu_intfs_total == 1:
                    self.interface_table.add_row(
                        "spanning-tree bpduguard enable (All access interfaces)", PASS
                    )
            except ZeroDivisionError:
                self.interface_table.add_row(
                    f"spanning-tree bpduguard {ACC_INTF_VERIFY}", WARN
                )
        else:
            self.interface_table.add_row(
                "spanning-tree portfast bpduguard default ([cyan]Global[/cyan])",
                PASS,
            )

    def check_stp_root(self, parse: CiscoConfParse):
        root_intfs_total, root_intfs_pass = 0, 0
        root_intfs = parse.find_objects_w_child(
            parentspec=r"^interface\s", childspec=IS_ACCESS_PORT
        )
        for root_obj in root_intfs:
            if not root_obj.re_search_children(
                r"^\sspanning-tree\sguard\sroot$|^\sspanning-tree\srootguard$"
            ) and not root_obj.re_search_children(r"^\s+shutdown$"):
                self.interface_table.add_row(
                    f"{root_obj.text} spanning-tree guard root", FAIL
                )
            else:
                root_intfs_pass += 1
            root_intfs_total += 1
        try:
            if root_intfs_pass / root_intfs_total == 1:
                self.interface_table.add_row(
                    "spanning-tree guard root (All access interfaces)", PASS
                )
        except ZeroDivisionError:
            self.interface_table.add_row(
                f"spanning-tree guard root {ACC_INTF_VERIFY}", WARN
            )

    def check_cdp(self, parse: CiscoConfParse):
        if not bool(parse.find_objects(r"^no\scdp\srun$")):
            cdp_intfs_total, cdp_intfs_pass = 0, 0
            cdp_intfs = parse.find_objects_w_child(
                parentspec=r"^interface\s", childspec=IS_ACCESS_PORT
            )
            for cdp_obj in cdp_intfs:
                if not cdp_obj.re_search_children(
                    r"^\sno\scdp\senable$"
                ) and not cdp_obj.re_search_children(r"^\sshutdown$"):
                    self.interface_table.add_row(f"{cdp_obj.text} no cdp enable", FAIL)
                else:
                    cdp_intfs_pass += 1
                cdp_intfs_total += 1
            try:
                if cdp_intfs_pass / cdp_intfs_total == 1:
                    self.interface_table.add_row(
                        "no cdp enable (All access interfaces)", PASS
                    )
            except ZeroDivisionError:
                self.interface_table.add_row(f"no cdp enable {ACC_INTF_VERIFY}", WARN)
        else:
            self.interface_table.add_row("no cdp run ([cyan]Global[/cyan])", PASS)

    def check_lldp(self, parse: CiscoConfParse):
        if not bool(parse.find_objects(r"^no\slldp\srun$")):
            lldp_intfs_total, lldp_intfs_pass = 0, 0
            lldp_intfs = parse.find_objects_w_child(
                parentspec=r"^interface\s", childspec=IS_ACCESS_PORT
            )
            for lldp_obj in lldp_intfs:
                if (
                    not lldp_obj.re_search_children(r"^\sno\slldp\stransmit$")
                    and not lldp_obj.re_search_children(r"^\sno\slldp\sreceive$")
                    and not lldp_obj.re_search_children(r"^\sshutdown$")
                ):
                    self.interface_table.add_row(
                        f"'{lldp_obj.text}' no lldp transmit/receive", FAIL
                    )
                else:
                    lldp_intfs_pass += 1
                lldp_intfs_total += 1
            try:
                if lldp_intfs_pass / lldp_intfs_total == 1:
                    self.interface_table.add_row(
                        "no lldp transmit/receive (All access interfaces)", PASS
                    )
            except ZeroDivisionError:
                self.interface_table.add_row(
                    f"no lldp transmit/receive {ACC_INTF_VERIFY}", WARN
                )
        else:
            self.interface_table.add_row("no lldp run ([cyan]Global[/cyan])", PASS)

    def check_ip_src_verify(self, parse: CiscoConfParse):
        src_verify_total, src_verify_pass = 0, 0
        src_verify_intfs = parse.find_objects_w_child(
            parentspec=r"^interface\s", childspec=IS_ACCESS_PORT
        )
        for src_verify_obj in src_verify_intfs:
            if not src_verify_obj.re_search_children(
                r"^\sip\sverify\ssource$"
            ) and not src_verify_obj.re_search_children(r"^\sshutdown$"):
                self.interface_table.add_row(
                    f"'{src_verify_obj.text}' ip verify source", FAIL
                )
            else:
                src_verify_pass += 1
            src_verify_total += 1
        try:
            if src_verify_pass / src_verify_total == 1:
                self.interface_table.add_row(
                    "ip verify source (All access interfaces)", PASS
                )
        except ZeroDivisionError:
            self.interface_table.add_row(f"ip verify source {ACC_INTF_VERIFY}", WARN)

    def check_sticky_mac(self, parse: CiscoConfParse):
        mac_sticky_total, mac_stick_pass = 0, 0
        mac_sticky_intfs = parse.find_objects_w_child(
            parentspec=r"^interface\s", childspec=IS_ACCESS_PORT
        )
        for mac_sticky_obj in mac_sticky_intfs:
            if (
                not mac_sticky_obj.re_search_children(r"^\sswitchport\sport-security$")
                and mac_sticky_obj.re_search_children(
                    r"^\sswitchport\sport-security\smac-address\ssticky$"
                )
                and not mac_sticky_obj.re_search_children(r"^\sshutdown$")
            ):
                self.interface_table.add_row(
                    f"'{mac_sticky_obj.text}' switchport port-security mac-address sticky",
                    FAIL,
                )
            else:
                mac_stick_pass += 1
            mac_sticky_total += 1
        try:
            if mac_stick_pass / mac_sticky_total == 1:
                self.interface_table.add_row(
                    "switchport port-security (All access interfaces)", PASS
                )
        except ZeroDivisionError:
            self.interface_table.add_row(
                f"switchport port-security mac-address sticky {ACC_INTF_VERIFY}", WARN
            )

    # L3 interfaces
    def check_arp_proxy(self, parse: CiscoConfParse):
        if not bool(parse.find_objects(r"^ip\sarp\sproxy\sdisable$")):
            arp_intfs_total, arp_intfs_pass = 0, 0
            arp_intfs = parse.find_objects_w_child(
                parentspec=r"^interface\s", childspec=r"^\sip\saddress\s"
            )
            for arp_obj in arp_intfs:
                if not arp_obj.re_search_children(
                    r"^\sno\sip\sproxy-arp$"
                ) and not arp_obj.re_search_children(r"^\sshutdown$"):
                    self.interface_table.add_row(
                        f"'{arp_obj.text}' no ip proxy-arp", FAIL
                    )
                else:
                    arp_intfs_pass += 1
                arp_intfs_total += 1
            try:
                if arp_intfs_pass / arp_intfs_total == 1:
                    self.interface_table.add_row(
                        "no ip proxy-arp (All interfaces)", PASS
                    )
            except ZeroDivisionError:
                self.interface_table.add_row(f"no ip proxy-arp {L3_INTF_VERIFY}", FAIL)
        else:
            self.interface_table.add_row(
                "ip arp proxy disable ([cyan]Global[/cyan])", PASS
            )

    def check_ip_redirects(self, parse: CiscoConfParse):
        redirect_intfs_total, redirect_intfs_pass = 0, 0
        redirect_intfs = parse.find_objects_w_child(
            parentspec=r"^interface\s", childspec=r"^\sip\saddress\s"
        )
        for redirect_obj in redirect_intfs:
            if not redirect_obj.has_child_with(
                r"^\sno\sip\sredirects$"
            ) and not redirect_obj.has_child_with(r"^\sshutdown$"):
                self.interface_table.add_row(
                    f"'{redirect_obj.text}' no ip redirects", FAIL
                )
            else:
                redirect_intfs_pass += 1
            redirect_intfs_total += 1
        try:
            if redirect_intfs_pass / redirect_intfs_total == 1:
                self.interface_table.add_row("no ip redirects (All interfaces)", PASS)
        except ZeroDivisionError:
            self.interface_table.add_row(f"no ip redirects {L3_INTF_VERIFY}", FAIL)

    def check_route_cache(self, parse: CiscoConfParse):
        rcache_intfs_total, rcache_intfs_pass = 0, 0
        rcache_intfs = parse.find_objects_w_child(
            parentspec=r"^interface\s", childspec=r"^\sip\saddress\s"
        )
        for rcache_obj in rcache_intfs:
            if not rcache_obj.has_child_with(
                r"^\sno\sip\sroute-cache$"
            ) and not rcache_obj.has_child_with(r"^\sshutdown$"):
                self.interface_table.add_row(
                    f"'{rcache_obj.text}' no ip route-cache", FAIL
                )
            else:
                rcache_intfs_pass += 1
            rcache_intfs_total += 1
        try:
            if rcache_intfs_pass / rcache_intfs_total == 1:
                self.interface_table.add_row("no ip route-cache (All interfaces)", PASS)
        except ZeroDivisionError:
            self.interface_table.add_row(f"no ip route-cache {L3_INTF_VERIFY}", FAIL)

    def check_directed_broadcast(self, parse: CiscoConfParse):
        redirect_intfs_total, redirect_intfs_pass = 0, 0
        redirect_intfs = parse.find_objects_w_child(
            parentspec=r"^interface\s", childspec=r"^\sip\saddress\s"
        )
        for redirect_obj in redirect_intfs:
            if not redirect_obj.re_search_children(
                r"^\sno\sip\sdirected-broadcast$"
            ) and not redirect_obj.re_search_children(r"^\sshutdown$"):
                self.interface_table.add_row(
                    f"'{redirect_obj.text}' no ip directed-broadcast", FAIL
                )
            else:
                redirect_intfs_pass += 1
            redirect_intfs_total += 1
        try:
            if redirect_intfs_pass / redirect_intfs_total == 1:
                self.interface_table.add_row(
                    "ip directed-broadcast (All interfaces)", PASS
                )
        except ZeroDivisionError:
            self.interface_table.add_row(
                f"ip directed-broadcast {L3_INTF_VERIFY}", FAIL
            )

    def check_ip_unreachables(self, parse: CiscoConfParse):
        unreachable_intfs_total, unreachable_intfs_pass = 0, 0
        unreachable_intfs = parse.find_objects_w_child(
            parentspec=r"^interface\s", childspec=r"^\sip\saddress\s"
        )
        for unreachable_obj in unreachable_intfs:
            if unreachable_obj.re_search_children(
                r"^\sip\sunreachables$"
            ) and not unreachable_obj.re_search_children(r"^\sshutdown$"):
                self.interface_table.add_row(
                    f"'{unreachable_obj.text}' no ip unreachables", FAIL
                )
            else:
                unreachable_intfs_pass += 1
            unreachable_intfs_total += 1

        try:
            if unreachable_intfs_pass / unreachable_intfs_total == 1:
                self.interface_table.add_row(
                    "no ip unreachables ([cyan]All L3 interfaces[/cyan])", PASS
                )
        except ZeroDivisionError:
            self.interface_table.add_row(f"no ip unreachables {L3_INTF_VERIFY}", FAIL)

    def check_lines(self, parse: CiscoConfParse):
        lines_total, lines_pass = 0, 0
        lines = parse.find_objects(r"^line\svty\s")
        msg = "{0:s} --> transport input ssh"
        for line_obj in lines:
            if not line_obj.re_search_children(r"^\stransport\sinput\sssh$"):
                self.interface_table.add_row(msg.format(line_obj.text), FAIL)
            else:
                self.interface_table.add_row(msg.format(line_obj.text), PASS)
                lines_pass += 1
            if not line_obj.re_search_children(r"^\sexec-timeout\s10\s0$"):
                self.interface_table.add_row(
                    f"{line_obj.text} --> exec-timeout 10 0", FAIL
                )
            if not line_obj.re_search_children(r"^\slogging\ssynchronous$"):
                self.interface_table.add_row(
                    f"{line_obj.text} --> logging synchronous", RECOMMENDED
                )
            lines_total += 1
        try:
            if lines_pass / lines_total == 1:
                self.interface_table.add_row(
                    "transport input ssh ([cyan]All VTY lines[/cyan])", PASS
                )
        except ZeroDivisionError:
            self.interface_table.add_row("transport input ssh", FAIL)

    def get_report(self):
        if self.global_table is not None:
            self.console.print(self.global_table)
        if self.interface_table is not None:
            self.console.print(self.interface_table)
