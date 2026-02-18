# DomainPeek — CLI DNS Testing Toolkit

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)
[![GitHub issues](https://img.shields.io/github/issues/nulltree-software/DomainPeek)](https://github.com/nulltree-software/DomainPeek/issues)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20macOS%20%7C%20linux-lightgrey)

**DomainPeek** is a command-line DNS testing toolkit that retrieves DNS, WHOIS, email authentication, and diagnostic data for any domain — all using native Python libraries.
Built for sysadmins, MSPs, and IT professionals who need to investigate and troubleshoot domain configurations without relying on external tools like `dig` or `whois`.


## Features

*   **Platform Independent:** Runs anywhere Python runs.
*   Retrieves **Domain Registrant** (Registered owner name/organization).
*   Retrieves **Domain Registrar** (The company managing the domain registration).
*   Lists **Authoritative Nameservers** (NS Records) for the domain.
*   Infers the **DNS Hosting Provider** by performing a WHOIS lookup on the *owner domain* of the primary nameserver.
*   **Email Authentication** (`-m`): Checks DMARC, SPF, and DKIM records.
*   **DNS Propagation** (`-p`): Compares DNS records across 8 public resolvers to identify inconsistencies.
*   **DNS Trace** (`-t`): Traces the delegation chain from root servers to authoritative nameservers (like `dig +trace`).
*   **Full Diagnostic** (`-d`): Runs all checks — SOA analysis, DNSSEC validation, TTL report, reverse DNS, authoritative vs recursive comparison, plus propagation, trace, and email auth.
*   **Bulk Checking** (`-b`): Check multiple domains at once from a CSV or JSON file.
*   **Export Results** (`-e`): Export results to a `.txt`, `.json`, or `.csv` file.
*   **Custom Resolver** (`-r`): Override the default DNS resolver.
*   **Local Resolver** (`-l`): Include an internal/local resolver in propagation checks.


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

```bash
domainpeek google.com -m
domainpeek google.com --mail-authentication
```


### Bulk Domain Checking (`-b`)

Check multiple domains from a file using the `-b` or `--bulk` flag. When using bulk mode, do not provide a domain as a positional argument.

```bash
domainpeek -b domains.csv
domainpeek --bulk domains.json
domainpeek -b domains.csv -m
domainpeek -b domains.csv -d -e report.json
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
domainpeek -b domains.json -d -e full_report.json
```

**Supported export formats:**
*   `.txt` — Human-readable text output (same format as terminal output)
*   `.json` — Structured JSON data
*   `.csv` — Tabular CSV with flattened fields

When exporting, progress is displayed in the terminal while results are written to the file.


### DNS Propagation (`-p`)

Check how a domain's DNS records appear across 8 major public resolvers. This is useful for verifying DNS changes have propagated globally or identifying split-horizon issues.

```bash
domainpeek google.com -p
domainpeek google.com --propagation
```

The tool queries **A**, **AAAA**, **NS**, and **MX** records against:
*   Google (8.8.8.8)
*   Cloudflare (1.1.1.1)
*   Quad9 (9.9.9.9)
*   OpenDNS (208.67.222.222)
*   Level3 (209.244.0.3)
*   Verisign (64.6.64.6)
*   CleanBrowsing (185.228.168.9)
*   AdGuard (94.140.14.14)

Results are compared and a consensus status is shown for each record type (ALL AGREE or MISMATCH).


### DNS Trace (`-t`)

Trace the delegation chain from root DNS servers down through TLD servers to the authoritative nameservers, similar to `dig +trace`. Shows response times at each hop.

```bash
domainpeek google.com -t
domainpeek google.com --trace
```


### Full Diagnostic (`-d`)

Run a comprehensive diagnostic with a single command. This automatically enables email authentication (`-m`), propagation (`-p`), and trace (`-t`), plus additional checks:

*   **SOA Record Analysis** — Primary NS, admin email, serial number, refresh/retry/expire timers.
*   **DNSSEC Validation** — Checks for DS and DNSKEY records, verifies RRSIG presence.
*   **TTL Report** — Reports the TTL for A, AAAA, NS, MX, SOA, and TXT records.
*   **Reverse DNS (PTR)** — Performs PTR lookups on discovered A record IPs.
*   **Authoritative vs Recursive** — Compares A and MX results from the authoritative nameserver against a public recursive resolver to detect mismatches.

```bash
domainpeek google.com -d
domainpeek google.com --diagnose
```

This is the recommended mode for troubleshooting DNS issues — it tests as much of the DNS stack as possible in a single run.


### Local Resolver (`-l`)

Include an internal or local DNS server in the propagation check, allowing you to compare local results against public resolvers. Useful for diagnosing split-horizon DNS or internal caching issues.

```bash
domainpeek google.com -p -l 192.168.1.1
domainpeek google.com -d -l 10.0.0.53
```

If `-l` is used without `-p` or `-d`, propagation mode is automatically enabled.


### Custom Resolver (`-r`)

Override the default system resolver for standard queries (basic lookup, mail auth, diagnostics). This does not affect the propagation check resolvers.

```bash
domainpeek google.com -r 1.1.1.1
domainpeek google.com -d -r 8.8.8.8
```


### Combining Flags

All flags can be combined freely. Some examples:

```bash
# Full diagnostic with local resolver, exported to JSON
domainpeek google.com -d -l 192.168.1.1 -e report.json

# Bulk check with propagation and mail auth
domainpeek -b domains.csv -p -m

# Trace with custom resolver
domainpeek google.com -t -r 1.1.1.1

# Everything: bulk + full diagnostic + export
domainpeek -b domains.csv -d -e full_report.json
```


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

When exporting to **JSON**, results are output as an array of structured objects containing all fields. When exporting to **CSV**, nested fields (nameservers, DKIM selectors, propagation data, etc.) are flattened and joined with semicolons.


## Flag Reference

| Flag | Long Form | Description |
|------|-----------|-------------|
| (positional) | | Domain name to check |
| `-m` | `--mail-authentication` | Check SPF, DMARC, and DKIM records |
| `-b FILE` | `--bulk FILE` | Bulk check domains from CSV or JSON file |
| `-e FILE` | `--export FILE` | Export results to .txt, .json, or .csv |
| `-p` | `--propagation` | Compare DNS across 8 public resolvers |
| `-t` | `--trace` | Trace delegation chain from root servers |
| `-d` | `--diagnose` | Full diagnostic (enables -m, -p, -t + SOA/DNSSEC/TTL/PTR) |
| `-l IP` | `--local-resolver IP` | Include a local resolver in propagation checks |
| `-r IP` | `--resolver IP` | Override default resolver for standard queries |


## License

This project is licensed under the MIT License.


## Issues

Please report any bugs or feature requests through the GitHub Issues page for this repository.
