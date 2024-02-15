# Cisco Config Auditor

[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/Tes3awy/cisco-config-auditor)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/ciscoconfaudit)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg?style=flat-square)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat-square&labelColor=ef8336)](https://pycqa.github.io/isort/)
![LICENSE](https://img.shields.io/github/license/Tes3awy/cisco-config-auditor?color=purple&style=flat-square&label=LICENSE)
![Commit Activity](https://img.shields.io/github/commit-activity/m/Tes3awy/cisco-config-auditor/main?logo=github&style=flat-square)
[![Say Thanks!](https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg)](https://saythanks.io/to/Tes3awy)

> Based on [Use Cisco IOS XE Hardening Guide](https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/ios-xe-16/220270-use-cisco-ios-xe-hardening-guide.html) and some opinionated best practices.

This package gives an overview of the hardening techniques that can be used to secure a Cisco network device. Network security is not a one-layer thing, yet, it depends on multiple factors. If you harden your devices, then it is a good starting point that increases the overall security of the environment you manage.

## Installation

> Install from PyPi

```bash
$ pip install ciscoconfaudit
```

## Usage

You can try out _two examples_ in the repo.

```bash
(.venv) $ python3 basic_online.py   # Parses config from a device (Uses netmiko)
(.venv) $ python3 basic_offline.py  # Parses config from text file
```

### Example Output

| Global Config Audit (Sample)                                                                                     | Interface-Level Audit                                                                                                |
| ---------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| ![Global Config Audit](https://github.com/Tes3awy/cisco-config-auditor/blob/main/assets/global-config-audit.jpg) | ![Interface Level Audit](https://github.com/Tes3awy/cisco-config-auditor/blob/main/assets/interface-level-audit.jpg) |

## USE CASE

- Ever been tired of checking whether the Cisco hardneing technqiues (_[here](https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/ios-xe-16/220270-use-cisco-ios-xe-hardening-guide.html)_) are applied to your network devices one by one? This package is very handy in generating a tabular report for you.

## Credits

This package was inspired by [jonarm](https://github.com/jonarm) from [cisco-ios-audit](https://github.com/jonarm/cisco-ios-audit).

## Author

[Osama Abbas](https://github.com/Tes3awy)

## Contributions

You are welcome to contribute to this Cisco [Swiss army knife](https://en.wikipedia.org/wiki/Swiss_Army_knife).
