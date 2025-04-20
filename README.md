# DomainPeek CLI DNS Insights

A command-line tool to quickly retrieve essential DNS, WHOIS, and basic Email Authentication information for a given domain using native Python libraries. Designed for MSPs and IT professionals needing to investigate domain configurations without relying on external command-line utilities like `dig` or `whois`.


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

Run the tool from your command line, providing the domain name you want to check as an argument. Optionally include the mail authentication flag.

`domainpeek <domain_name>`

Example usage: `domainpeek google.com`


Including the `-m` or `--mail-authentication` flag outputs basic Email Authentication checks for SPF and DMARC

Example usage: `domainpeek google.com -m` or `domainpeek google.com --mail-authentication`


### Output Explanation

The tools default output displays basic domain and DNS info:
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

## License

This project is licensed under the MIT License.


## Issues

Please report any bugs or feature requests through the GitHub Issues page for this repository.