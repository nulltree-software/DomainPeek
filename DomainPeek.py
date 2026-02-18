#!/usr/bin/env python3
import argparse
import sys
import json
import csv
import io
import os
import tldextract
import whois
import dns.resolver
import socket
from typing import List, Tuple, Optional, Any, Dict


# Dictionary of common Selectors for checking DKIM Records 
# Can be extended to include major providers like SendGrid, Mailgun, etc
COMMON_DKIM_SELECTORS = [
    "google",      # Google Workspace
    "selector1",   # Microsoft 365, others
    "selector2",   # Microsoft 365, others
    "k1",          # General/Common
    "k2",          # General/Common
    "k3",          # General/Common
    "default",     # Common fallback
    "m1",          # Mailchimp? Others?
    "mandrill",    # Mandrill (Mailchimp Transactional)
    "dkim",        # Generic
    "zoho",        # Zoho Mail
    "s1",          # SendGrid? Generic?
    "s2",          # SendGrid? Generic?
    "email",       # SendGrid? Generic?
]


# Dictionary for Known DNS Provider Nameserver patterns
KNOWN_PROVIDER_PATTERNS = {
    "cloudflare.com":           "Cloudflare",
    "google.com":               "Google Cloud DNS / Google Workspace",
    "googlehosted.com":         "Google Workspace",
    "googledomains.com":        "Google Domains",
    "azure-dns":                "Microsoft Azure DNS",
    "microsoftonline.com":      "Microsoft Azure DNS / M365",
    "microsoft.com":            "Microsoft Azure DNS / M365"
}

# Helper function to safely get WHOIS data
def get_whois_info(domain: str, warnings: Optional[List[str]] = None) -> Optional[Any]:
    """Performs a WHOIS lookup for the domain and handles common errors."""
    def _warn(msg: str):
        if warnings is not None:
            warnings.append(msg)
        else:
            print(msg, file=sys.stderr)

    try:
        # timeout parameter might not be supported by all underlying whois libs/servers
        # The default whois library might follow redirects, which can be slow.
        return whois.whois(domain)
    except whois.exceptions.UnknownTld:
        _warn(f"Warning: WHOIS lookup failed for '{domain}'. Unknown TLD.")
        return None
    except whois.exceptions.WhoisCommandFailed as e:
        _warn(f"Warning: WHOIS command execution failed for '{domain}': {e}")
        return None
    except whois.exceptions.PywhoisError as e: # General catch-all for the library
        _warn(f"Warning: WHOIS lookup error for '{domain}': {e}")
        return None
    except socket.timeout:
        _warn(f"Warning: WHOIS lookup for '{domain}' timed out.")
        return None
    except Exception as e: # Catch any other unexpected errors
        _warn(f"Warning: An unexpected error occurred during WHOIS lookup for '{domain}': {e}")
        return None

# Helper function to get DNS records
def get_dns_records(domain: str, record_type: str) -> Tuple[List[str], Optional[str]]:
    """
    Performs a DNS lookup for the specified record type and handles common errors.
    Returns a list of record strings and an optional error message.
    """
    records = []
    error_msg = None
    try:
        resolver = dns.resolver.Resolver()
        # resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        answer = resolver.resolve(domain, record_type, raise_on_no_answer=False) # Don't raise, check rrset

        if answer.rrset is None:
            # Handles CNAMEs implicitly for A/AAAA lookups
            # No answer means no explicit NS records found at this level
            if record_type == 'NS':
                 # Check if it's possibly a CNAME pointing elsewhere
                 try:
                     cname_answer = resolver.resolve(domain, 'CNAME')
                     if cname_answer.rrset:
                          cname_target = cname_answer.rrset[0].to_text().rstrip('.')
                          error_msg = f"No direct {record_type} records found, but found CNAME: {cname_target}"
                     else:
                          error_msg = f"No {record_type} records found."
                 except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                      error_msg = f"No {record_type} records found."
            else:
                error_msg = f"No {record_type} records found."
            return [], error_msg

        # Process the found records
        for rdata in answer:
            record_text = rdata.to_text().strip().rstrip('.') # Clean trailing dot
            if record_type == 'TXT' and record_text.startswith('"') and record_text.endswith('"'):
                 # Remove surrounding quotes and handle potential internal quote escaping
                 record_text = record_text[1:-1].replace('\\"', '"').replace('\\\\', '\\')
            records.append(record_text)

    except dns.resolver.NXDOMAIN:
        error_msg = f"Domain '{domain}' does not exist (NXDOMAIN)."
    except dns.resolver.NoAnswer:
        # This is now handled by raise_on_no_answer=False and checking rrset,
        # but kept here as a safeguard or for other potential scenarios.
        error_msg = f"No {record_type} records found for '{domain}'."
    except dns.resolver.NoNameservers:
        error_msg = f"Could not contact nameservers for '{domain}'."
    except dns.resolver.Timeout:
        error_msg = f"DNS query for {record_type} records of '{domain}' timed out."
    except Exception as e:
        error_msg = f"An unexpected DNS error occurred for '{domain}' ({record_type}): {e}"

    if not records and not error_msg:
         error_msg = f"No {record_type} records found (or query failed silently)."

    return records, error_msg


# Helper function to extract primary value from WHOIS results
def get_primary_whois_value(data: Optional[Any]) -> str:
    """Gets the primary string value from WHOIS result (handles lists/None)."""
    if data is None:
        return "Not Found"
    if isinstance(data, list):
        # Often the first item is the primary one, filter empty strings
        filtered_list = [item for item in data if isinstance(item, str) and item.strip()]
        return filtered_list[0] if filtered_list else "Not Found"
    elif isinstance(data, str):
        return data.strip() if data.strip() else "Not Found"
    else:
        return str(data) # Fallback

# Extracts Registrable Domain using tldextract
def get_registrable_domain(fqdn: str, warnings: Optional[List[str]] = None) -> Optional[str]:
    """
    Extracts the registrable domain (e.g., example.com, example.co.uk)
    from a fully qualified domain name (e.g., ns1.example.com) using tldextract.
    """
    def _warn(msg: str):
        if warnings is not None:
            warnings.append(msg)
        else:
            print(msg, file=sys.stderr)

    if not fqdn:
        return None
    try:
        ext = tldextract.extract(fqdn, include_psl_private_domains=True)
        if ext.registered_domain:
             return ext.registered_domain
        else:
            _warn(f"Warning: Could not extract registrable domain from '{fqdn}'")
            return None
    except Exception as e:
        _warn(f"Error using tldextract on {fqdn}: {e}")
        return None


# SPF check (filters TXT)
def check_spf(domain: str) -> Tuple[Optional[str], Optional[str]]:
    """Checks for SPF record (TXT starting with 'v=spf1')."""
    txt_records, error_msg = get_dns_records(domain, 'TXT')
    if error_msg and not txt_records:
        return None, error_msg # Return error if lookup failed entirely

    spf_record = None
    for record in txt_records:
        # Use lower() for case-insensitive check, but return original case
        if record.lower().startswith("v=spf1"):
            spf_record = record # Found it
            break # Assume only one primary SPF per domain spec

    # Handle case where TXT records exist but none are SPF
    if not spf_record and txt_records:
        return None, None # No SPF record found among existing TXT

    # Handle case where get_dns_records returned an error _or_ no TXT found
    if not spf_record and not txt_records:
        if error_msg and "No TXT records found" not in error_msg:
             return None, error_msg # Return original lookup error
        else:
             return None, None # Explicitly no SPF found

    return spf_record, None # Return found record, no error


def check_common_dkim(domain: str) -> Tuple[Dict[str, List[str]], Optional[str]]:
    """
    Checks for DKIM TXT records using a list of common selectors.
    Returns a dictionary of found {selector: [records]} and an optional general error message.
    Specific 'selector not found' errors are ignored.
    """
    found_dkim: Dict[str, List[str]] = {}
    general_error: Optional[str] = None

    for selector in COMMON_DKIM_SELECTORS:
        dkim_domain = f"{selector}._domainkey.{domain}"
        records, error_msg = get_dns_records(dkim_domain, 'TXT')

        if records:
            found_dkim[selector] = records
        elif error_msg:
            # Only store general errors, ignore NXDOMAIN/NoAnswer which mean the selector just doesn't exist
            is_specific_not_found = "NXDOMAIN" in error_msg or "No TXT records found" in error_msg
            if not is_specific_not_found and not general_error:
                # Store the first general error encountered (like Timeout)
                general_error = f"Error during DKIM lookups ({selector}): {error_msg}"

    return found_dkim, general_error


# --- Input File Parsers ---

def load_domains_from_csv(filepath: str) -> List[str]:
    """
    Reads domains from a CSV file. Expects one domain per row in the first column.
    Skips rows that look like headers and blank rows.
    """
    domains = []
    with open(filepath, 'r', newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        for i, row in enumerate(reader):
            if not row or not row[0].strip():
                continue
            value = row[0].strip()
            # Skip header row
            if i == 0 and value.lower() in ('domain', 'domain_name', 'hostname', 'host'):
                continue
            domains.append(value)
    return domains


def load_domains_from_json(filepath: str) -> List[str]:
    """
    Reads domains from a JSON file.
    Supports: array of strings ["example.com", ...]
              or array of objects [{"domain": "example.com"}, ...]
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("JSON file must contain an array at the top level.")

    domains = []
    for item in data:
        if isinstance(item, str):
            d = item.strip()
            if d:
                domains.append(d)
        elif isinstance(item, dict):
            d = item.get('domain', '').strip()
            if d:
                domains.append(d)
            else:
                raise ValueError(f"JSON object missing 'domain' key: {item}")
        else:
            raise ValueError(f"Unexpected item type in JSON array: {type(item).__name__}")
    return domains


def load_domains(filepath: str) -> List[str]:
    """Loads domains from a CSV or JSON file based on extension."""
    ext = os.path.splitext(filepath)[1].lower()
    if ext == '.json':
        return load_domains_from_json(filepath)
    elif ext in ('.csv', '.txt', ''):
        return load_domains_from_csv(filepath)
    else:
        raise ValueError(f"Unsupported input file format '{ext}'. Use .csv or .json.")


# --- Core Domain Check ---

def check_domain(domain_input: str, check_mail: bool = False) -> Dict[str, Any]:
    """
    Performs all checks for a single domain and returns a structured result dict.
    Does not print anything to stdout.
    """
    domain_to_check = domain_input.lower().strip()
    warn_list: List[str] = []

    result: Dict[str, Any] = {
        "domain": domain_to_check,
        "registrant": "Not Found",
        "registrar": "Not Found",
        "nameservers": [],
        "nameserver_error": None,
        "dns_hosting_provider": "Not Found / Unable to Determine",
        "mail_authentication": None,
        "warnings": warn_list,
    }

    # Get Domain Registrant & Registrar via WHOIS
    domain_whois = get_whois_info(domain_to_check, warnings=warn_list)

    if domain_whois:
        registrant_name = get_primary_whois_value(domain_whois.get('name') or domain_whois.get('registrant_name'))
        registrant_org = get_primary_whois_value(domain_whois.get('org') or domain_whois.get('registrant_organization'))

        if registrant_name != "Not Found":
            result["registrant"] = registrant_name
        elif registrant_org != "Not Found":
            result["registrant"] = registrant_org

        registrar = get_primary_whois_value(domain_whois.get('registrar'))
        if registrar == "Not Found":
            url = get_primary_whois_value(domain_whois.get('registrar_url'))
            if url != "Not Found":
                registrar = f"URL: {url}"
        result["registrar"] = registrar
    else:
        result["registrant"] = "WHOIS Lookup Failed"
        result["registrar"] = "WHOIS Lookup Failed"

    # Get Nameservers (NS Records) via DNS
    nameservers, ns_error_msg = get_dns_records(domain_to_check, 'NS')

    first_nameserver = None
    if ns_error_msg:
        result["nameserver_error"] = ns_error_msg
    elif nameservers:
        result["nameservers"] = nameservers
        first_nameserver = nameservers[0]

    # Get DNS Hosting Provider
    dns_hosting_provider = "Not Found / Unable to Determine"
    provider_detected = False

    if first_nameserver:
        ns_lower = first_nameserver.lower()

        for pattern, provider_name in KNOWN_PROVIDER_PATTERNS.items():
            if pattern in ns_lower:
                dns_hosting_provider = provider_name
                provider_detected = True
                break

        if not provider_detected:
            ns_owner_domain = get_registrable_domain(first_nameserver, warnings=warn_list)
            if ns_owner_domain:
                ns_domain_whois = get_whois_info(ns_owner_domain, warnings=warn_list)
                if ns_domain_whois:
                    inferred_provider = get_primary_whois_value(ns_domain_whois.get('registrar'))
                    if inferred_provider == "Not Found":
                        org = get_primary_whois_value(ns_domain_whois.get('org'))
                        dns_hosting_provider = f"Inferred: {org} (Org)" if org != "Not Found" else "Inferred: Registrar/Org Not Found in WHOIS"
                    else:
                        dns_hosting_provider = f"Inferred: {inferred_provider} (Registrar)"
                else:
                    dns_hosting_provider = f"Inferred: WHOIS Lookup Failed for {ns_owner_domain}"
            else:
                dns_hosting_provider = "Inferred: Could not determine owner domain from NS"
    else:
        dns_hosting_provider = "Skipped (No nameserver found)"

    result["dns_hosting_provider"] = dns_hosting_provider

    # Email Authentication checks
    if check_mail:
        # DMARC
        dmarc_domain = f"_dmarc.{domain_to_check}"
        dmarc_records, dmarc_error = get_dns_records(dmarc_domain, 'TXT')
        dmarc_result = {"record": None, "error": None}
        if dmarc_error and not dmarc_records:
            dmarc_result["error"] = dmarc_error
        elif dmarc_records:
            dmarc_result["record"] = dmarc_records[0]

        # SPF
        spf_record, spf_error = check_spf(domain_to_check)
        spf_result = {"record": spf_record, "error": spf_error}

        # DKIM
        found_dkim, dkim_general_error = check_common_dkim(domain_to_check)
        dkim_result = {"found": found_dkim, "error": dkim_general_error}

        result["mail_authentication"] = {
            "dmarc": dmarc_result,
            "spf": spf_result,
            "dkim": dkim_result,
        }

    return result


# --- Output Formatters ---

def format_text_result(result: Dict[str, Any]) -> str:
    """Formats a single domain result as human-readable text (matches original output)."""
    lines = []
    domain = result["domain"]
    lines.append(f"--- Checking Domain: {domain} ---\n")
    lines.append(f"Domain Registrant: {result['registrant']}")
    lines.append(f"Domain Registrar: {result['registrar']}")

    if result.get("nameserver_error"):
        lines.append(f"Error: {result['nameserver_error']}")
    elif result.get("nameservers"):
        lines.append(f"Nameservers: {', '.join(result['nameservers'])}")
    else:
        lines.append("No nameservers identified.")

    lines.append(f"DNS Hosting Provider: {result['dns_hosting_provider']}")

    mail = result.get("mail_authentication")
    if mail:
        lines.append("\n--- Email Authentication ---")

        # DMARC
        dmarc = mail["dmarc"]
        dmarc_domain = f"_dmarc.{domain}"
        if dmarc["error"] and not dmarc["record"]:
            lines.append(f"\nDMARC ({dmarc_domain}): \nError - {dmarc['error']}")
        elif dmarc["record"]:
            lines.append(f"\nDMARC ({dmarc_domain}): \n{dmarc['record']}")
        else:
            lines.append(f"\nDMARC ({dmarc_domain}): \nNot Found")

        # SPF
        spf = mail["spf"]
        if spf["error"]:
            lines.append(f"\nSPF ({domain}): \nError - {spf['error']}")
        elif spf["record"]:
            lines.append(f"\nSPF ({domain}): \n{spf['record']}")
        else:
            lines.append(f"\nSPF ({domain}): \nNot Found")

        # DKIM
        dkim = mail["dkim"]
        if dkim["error"]:
            lines.append(f"\nDKIM: \n{dkim['error']}")
        if dkim["found"]:
            lines.append("\nDKIM:")
            for selector, records in dkim["found"].items():
                for record in records:
                    lines.append(f"Selector '{selector}': {record[:80]}{'...' if len(record) > 80 else ''}")
        elif not dkim["error"]:
            lines.append("\nDKIM: \nNo records found using common selectors.")
        lines.append("\n(Note: This only checks common selectors, others may exist.)")

    lines.append(f"\n--- Check Complete for: {domain} ---")
    return "\n".join(lines)


def results_to_json(results: List[Dict[str, Any]]) -> str:
    """Converts a list of domain results to a JSON string."""
    return json.dumps(results, indent=2, default=str)


def results_to_csv(results: List[Dict[str, Any]]) -> str:
    """Converts a list of domain results to CSV format with flattened fields."""
    output = io.StringIO()
    fieldnames = [
        'domain', 'registrant', 'registrar', 'nameservers',
        'nameserver_error', 'dns_hosting_provider',
        'dmarc_record', 'dmarc_error', 'spf_record', 'spf_error',
        'dkim_selectors_found', 'dkim_error', 'warnings'
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for r in results:
        flat: Dict[str, str] = {
            'domain': r['domain'],
            'registrant': r['registrant'],
            'registrar': r['registrar'],
            'nameservers': '; '.join(r.get('nameservers') or []),
            'nameserver_error': r.get('nameserver_error') or '',
            'dns_hosting_provider': r['dns_hosting_provider'],
            'warnings': '; '.join(r.get('warnings') or []),
        }
        mail = r.get('mail_authentication')
        if mail:
            flat['dmarc_record'] = mail['dmarc']['record'] or ''
            flat['dmarc_error'] = mail['dmarc']['error'] or ''
            flat['spf_record'] = mail['spf']['record'] or ''
            flat['spf_error'] = mail['spf']['error'] or ''
            dkim_parts = []
            for sel, recs in mail['dkim']['found'].items():
                dkim_parts.append(f"{sel}={recs[0][:60]}")
            flat['dkim_selectors_found'] = '; '.join(dkim_parts)
            flat['dkim_error'] = mail['dkim']['error'] or ''
        else:
            for field in ['dmarc_record', 'dmarc_error', 'spf_record', 'spf_error',
                          'dkim_selectors_found', 'dkim_error']:
                flat[field] = ''
        writer.writerow(flat)
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(
        description="""
Get DNS and WHOIS info for a domain using Python libraries.
Optionally check common email authentication records (SPF, DMARC, DKIM).

Outputs basic info by default. Use -m for Email Authentication checks.
Use -b to check multiple domains from a CSV or JSON file.
Use -e to export results to a file (.txt, .json, or .csv).

Default Output Definitions:
  - Registrant: The person or organisation who registered the domain.
  - Registrar: The company managing the domain's registration.
  - Nameservers: The Authoritative DNS Servers listed for the domain.
  - DNS Hosting Provider: The platform inferred to host the DNS Records
    (determined by WHOIS lookup on the nameserver's owner domain).

Email Authentication (-m) Definitions:
  - DMARC: (Domain-based Message Authentication, Reporting, and Conformance)
           A policy (TXT record at _dmarc.) telling receiving servers how
           to handle messages failing SPF/DKIM checks (reject, quarantine, none).
  - SPF:   (Sender Policy Framework) A TXT record listing authorised servers
           allowed to send email on behalf of the domain. Helps prevent spoofing.
  - DKIM:  (DomainKeys Identified Mail) A digital signature (added by sending
           server, key published in DNS TXT at selector._domainkey.) verifying
           message integrity and origin. Tool checks common selectors.
""",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "domain",
        nargs='?',
        default=None,
        help="The domain name to check (e.g., example.com). Not required when using --bulk."
    )
    parser.add_argument(
        "-m", "--mail-authentication",
        action="store_true",
        help="Check for SPF, DMARC and DKIM records."
    )
    parser.add_argument(
        "-b", "--bulk",
        metavar="FILE",
        help="Path to a CSV or JSON file containing domains to check in bulk."
    )
    parser.add_argument(
        "-e", "--export",
        metavar="FILE",
        help="Export results to a file. Format is determined by extension (.txt, .json, .csv)."
    )
    args = parser.parse_args()

    # Validate: must have either domain or --bulk, not both, not neither
    if not args.domain and not args.bulk:
        parser.error("Please provide a domain name or use --bulk with a file path.")
    if args.domain and args.bulk:
        parser.error("Cannot use both a domain argument and --bulk. Use one or the other.")

    # Load domains
    if args.bulk:
        try:
            domains = load_domains(args.bulk)
        except FileNotFoundError:
            print(f"Error: File not found: {args.bulk}", file=sys.stderr)
            sys.exit(1)
        except (ValueError, json.JSONDecodeError) as e:
            print(f"Error reading '{args.bulk}': {e}", file=sys.stderr)
            sys.exit(1)

        if not domains:
            print(f"Error: No domains found in '{args.bulk}'.", file=sys.stderr)
            sys.exit(1)

        print(f"Loaded {len(domains)} domain(s) from '{args.bulk}'.",
              file=sys.stderr if args.export else sys.stdout)
    else:
        domains = [args.domain]

    # Validate export path early
    if args.export:
        export_ext = os.path.splitext(args.export)[1].lower()
        if export_ext not in ('.txt', '.json', '.csv'):
            print(f"Error: Unsupported export format '{export_ext}'. Use .txt, .json, or .csv.",
                  file=sys.stderr)
            sys.exit(1)
        export_dir = os.path.dirname(args.export) or '.'
        if not os.access(export_dir, os.W_OK):
            print(f"Error: Cannot write to directory '{export_dir}'.", file=sys.stderr)
            sys.exit(1)

    # Process domains
    results = []
    for i, domain_input in enumerate(domains):
        if args.export:
            # Progress to stderr so it doesn't contaminate export file
            print(f"[{i+1}/{len(domains)}] Checking {domain_input}...", file=sys.stderr)

        result = check_domain(domain_input, check_mail=args.mail_authentication)
        results.append(result)

        # Print warnings to stderr
        for w in result.get('warnings', []):
            print(w, file=sys.stderr)

        if not args.export:
            # Print human-readable output to stdout (existing behavior)
            print(format_text_result(result))
            if i < len(domains) - 1:
                print()  # Blank line between domains in bulk mode

    # Handle export
    if args.export:
        export_ext = os.path.splitext(args.export)[1].lower()
        try:
            if export_ext == '.json':
                content = results_to_json(results)
            elif export_ext == '.csv':
                content = results_to_csv(results)
            else:  # .txt
                content = "\n\n".join(format_text_result(r) for r in results)

            with open(args.export, 'w', encoding='utf-8') as f:
                f.write(content)

            print(f"\nResults exported to '{args.export}'.", file=sys.stderr)
        except IOError as e:
            print(f"Error writing to '{args.export}': {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
