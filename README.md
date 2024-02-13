# Cisco Config Auditor

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg?style=flat-square)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat-square&labelColor=ef8336)](https://pycqa.github.io/isort/)
![LICENSE](https://img.shields.io/github/license/Tes3awy/config-auditor?color=purple&style=flat-square&label=LICENSE)
![Commit Activity](https://img.shields.io/github/commit-activity/m/Tes3awy/config-auditor/main?logo=github&style=flat-square)

> Based on [Use Cisco IOS XE Hardening Guide](https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/ios-xe-16/220270-use-cisco-ios-xe-hardening-guide.html) and some opinionated best practices.

This script gives an overview of the hardening techniques that can be used to secure a Cisco network device. Security is not a one-layer thing, yet, it depends on multiple factors. If you harden your devices, then it is a good starting point that increases the overall security of the environment you manage.

## Installation

Clone repo, create a virtual environment, and install requirements.

### macOS or Linux

```bash
$ git clone ...
$ cd auditor
$ python3 -m venv .venv --upgrade-deps
$ source .venv/bin/activate .
(.venv) $ python3 -m pip install -r requirements.txt
```

### Windows

> In PowerShell

```pwsh
> git clone ...
> cd auditor
> python -m venv .venv --upgrade-deps
> .venv\Scripts\Activate.ps1
(.venv) > pip install -r requirements.txt
```

## Usage

You can try out two examples in the repo.

```bash
(.venv) $ python3 online.py   # parses config from a device (Uses netmiko)
(.venv) $ python3 offline.py  # parses config from text file
```

## Credits

This script was inspired by [jonarm](https://github.com/jonarm) from [cisco-ios-audit](https://github.com/jonarm/cisco-ios-audit).

## Author

[Osama Abbas](https://github.com/Tes3awy)

## Contibutions

You are welcome to contribute to this Cisco swiss-army knife.
