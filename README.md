# DomainPeek — CLI DNS Insights

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)
[![GitHub issues](https://img.shields.io/github/issues/nulltree-software/DomainPeek)](https://github.com/nulltree-software/DomainPeek/issues)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20macOS%20%7C%20linux-lightgrey)

**DomainPeek** is a command-line tool that retrieves essential DNS, WHOIS, and basic email authentication data for a given domain — all using native Python libraries.  
Built for sysadmins, MSPs, and IT professionals who need to investigate domain configurations without relying on tools like `dig` or `whois`.


## Features

*   **Platform Independent:** Runs anywhere Python runs.
*   Retrieves **Domain Registrant** (Registered owner name/organization).
*   Retrieves **Domain Registrar** (The company managing the domain registration).
*   Lists **Authoritative Nameservers** (NS Records) for the domain.
*   Infers the **DNS Hosting Provider** by performing a WHOIS lookup on the *owner domain* of the primary nameserver.
*   **Optional:** Checks basic **Email Authentication** records:
    *   **DMARC** (`_dmarc` TXT record)
    *   **SPF** (TXT record starting `v=spf1`)
    *   **DKIM** (Attempts to find records using a list of common selectors like `google`, `selector1`, `k1`, etc.)
*   **Bulk Checking:** Check multiple domains at once from a CSV or JSON file.
*   **Export Results:** Export results to a `.txt`, `.json`, or `.csv` file.


## Prerequisites

Before installing, ensure you have the following installed on your system:

1.  **Python 3.7+**
2.  **pip** (The Python package installer, typically included with Python)
3.  **Git** (Required by `pip` to clone the repository during installation)

### Installing Git

Windows: `winget install --id Git.Git -e --source winget`

Linux (Debian based ditributions): `sudo apt install git-all`

Other Linux distributions: `sudo dnf install git-all`

MacOS: `git --version`


## Installation

1.  **Prerequisites:** Ensure you have Python 3.7+ and Git installed and available in your system's PATH.
2.  **Install via pip:** Open your terminal (Command Prompt, PowerShell, Bash, etc.) and run:

    ```bash
    pip install git+https://github.com/nulltree-software/DomainPeek.git
    ```

    *To update an existing installation:*

    ```bash
    pip install --upgrade git+https://github.com/nulltree-software/DomainPeek.git
    ```

> **Important Note for Windows Users (PATH Environment Variable):**
>
> After installation, you might see a **WARNING** message in your terminal similar to this:
> ```
> WARNING: The script DomainPeel.exe is installed in 'C:\Users\YourUsername\AppData\Roaming\Python\Python312\Scripts' which is not on PATH.
> ```
> If you see this warning, the `domainpeek` command will **not** work immediately because Windows doesn't know where to find the executable.
>
> To resolve this **copy the exact directory path** shown in *your* warning message (e.g., `C:\Users\YourUsername\AppData\Roaming\Python\Python312\Scripts`) and **add this path** to your Windows **PATH Environment Variable**.


## Usage

Run the tool from your command line, providing the domain name you want to check as an argument.

`domainpeek <domain_name>`

Example usage: `domainpeek google.com`


### Email Authentication (`-m`)

Including the `-m` or `--mail-authentication` flag outputs basic Email Authentication checks for SPF, DMARC and DKIM.

Example usage: `domainpeek google.com -m` or `domainpeek google.com --mail-authentication`


### Bulk Domain Checking (`-b`)

Check multiple domains from a file using the `-b` or `--bulk` flag. When using bulk mode, do not provide a domain as a positional argument.

```bash
domainpeek -b domains.csv
domainpeek --bulk domains.json
domainpeek -b domains.csv -m
```

**Supported input formats:**

**CSV** — One domain per row (first column). Header rows containing common names like "domain" are automatically skipped.
```csv
domain
google.com
github.com
example.org
```

**JSON** — An array of domain strings, or an array of objects each with a `"domain"` key.
```json
["google.com", "github.com", "example.org"]
```
```json
[
  {"domain": "google.com"},
  {"domain": "github.com"},
  {"domain": "example.org"}
]
```


### Exporting Results (`-e`)

Export results to a file using the `-e` or `--export` flag. The output format is determined by the file extension.

```bash
domainpeek google.com -e results.json
domainpeek google.com -m -e results.txt
domainpeek -b domains.csv -e results.csv
domainpeek -b domains.json -m -e full_report.json
```

**Supported export formats:**
*   `.txt` — Human-readable text output (same format as terminal output)
*   `.json` — Structured JSON data
*   `.csv` — Tabular CSV with flattened fields

When exporting, progress is displayed in the terminal while results are written to the file.


### Output Explanation

The tool's default output displays basic domain and DNS info:
* Domain Registrant: Owner from WHOIS.
* Domain Registrar: Company managing registration (WHOIS).
* Nameservers: Authoritative servers from DNS (NS records).
* Inferred DNS Hosting Provider: Registrar/Org of the NS owner domain (WHOIS).

If the `-m` or `--mail-authentication` flag is used, it also outputs:
* DMARC: The content of the TXT record found at `_dmarc.<domain_name>`, or "Not Found" / Error message.
* SPF: The content of the TXT record for `<domain_name>` starting with `v=spf1`, or "Not Found" / Error message.
* DKIM: Any DKIM TXT records found by querying `{selector}._domainkey.<domain_name>` using a predefined list of common selectors (e.g., `google`, `selector1`, `k1`).
If records are found, the selector used will be displayed. If none are found using the common list, it will report that.
    * Note: This check is not exhaustive. Domains may use custom DKIM selectors that are not in the common list and therefore will not be found by this tool.

When exporting to **JSON**, results are output as an array of structured objects containing all fields. When exporting to **CSV**, nested fields (nameservers, DKIM selectors, warnings) are flattened and joined with semicolons.

## License

This project is licensed under the MIT License.


## Issues

Please report any bugs or feature requests through the GitHub Issues page for this repository.
