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
COMMON_DKIM_SELECTORS: List[str] = [
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
KNOWN_PROVIDER_PATTERNS: Dict[str, str] = {
    "cloudflare.com":           "Cloudflare",
    "google.com":               "Google Cloud DNS / Google Workspace",
    "googlehosted.com":         "Google Workspace",
    "googledomains.com":        "Google Domains",
    "azure-dns":                "Microsoft Azure DNS",
    "microsoftonline.com":      "Microsoft Azure DNS / M365",
    "microsoft.com":            "Microsoft Azure DNS / M365"
}

# Public DNS Resolvers for propagation checks
PUBLIC_RESOLVERS: Dict[str, str] = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
    "Level3": "209.244.0.3",
    "Verisign": "64.6.64.6",
    "CleanBrowsing": "185.228.168.9",
    "AdGuard": "94.140.14.14",
}

# Root DNS Servers for trace functionality
ROOT_SERVERS: List[Tuple[str, str]] = [
    ("a.root-servers.net", "198.41.0.4"),
    ("b.root-servers.net", "199.9.14.201"),
    ("c.root-servers.net", "192.33.4.12"),
    ("d.root-servers.net", "199.7.91.13"),
    ("e.root-servers.net", "192.203.230.10"),
]

# Helper function to safely get WHOIS data
def get_whois_info(domain: str, warnings: Optional[List[str]] = None) -> Optional[Any]:
    """Performs a WHOIS lookup for the domain and handles common errors."""
    def _warn(msg: str) -> None:
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
def get_dns_records(domain: str, record_type: str, nameserver: Optional[str] = None,
                    timeout: float = 5.0) -> Tuple[List[str], Optional[str], Optional[int]]:
    """
    Performs a DNS lookup for the specified record type and handles common errors.
    Returns a tuple of (record strings, error message, TTL).
    Optionally queries a specific nameserver.
    """
    records = []
    error_msg = None
    ttl = None
    try:
        resolver = dns.resolver.Resolver()
        if nameserver:
            resolver.nameservers = [nameserver]
        resolver.lifetime = timeout
        resolver.timeout = timeout
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
            return [], error_msg, None

        ttl = answer.rrset.ttl

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

    return records, error_msg, ttl


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
    def _warn(msg: str) -> None:
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
    txt_records, error_msg, _ = get_dns_records(domain, 'TXT')
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
        records, error_msg, _ = get_dns_records(dkim_domain, 'TXT')

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

def check_domain(domain_input: str, check_mail: bool = False,
                 check_propagation: bool = False, check_trace: bool = False,
                 check_diagnose: bool = False, local_resolver: Optional[str] = None,
                 custom_resolver: Optional[str] = None) -> Dict[str, Any]:
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
        "propagation": None,
        "trace": None,
        "diagnostics": None,
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
    nameservers, ns_error_msg, _ = get_dns_records(domain_to_check, 'NS', nameserver=custom_resolver)

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
        dmarc_records, dmarc_error, _ = get_dns_records(dmarc_domain, 'TXT', nameserver=custom_resolver)
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

    # DNS Toolkit checks (imported from dns_toolkit)
    if check_propagation:
        try:
            from dns_toolkit import run_propagation_check
            result["propagation"] = run_propagation_check(domain_to_check, local_resolver=local_resolver)
        except Exception as e:
            warn_list.append(f"Warning: Propagation check failed: {e}")

    if check_trace:
        try:
            from dns_toolkit import dns_trace
            result["trace"] = dns_trace(domain_to_check)
        except Exception as e:
            warn_list.append(f"Warning: DNS trace failed: {e}")

    if check_diagnose:
        try:
            from dns_toolkit import run_full_diagnostic
            first_ns_ip = None
            if first_nameserver:
                # Resolve the authoritative NS to an IP for direct queries
                try:
                    ns_ips, _, _ = get_dns_records(first_nameserver, 'A')
                    if ns_ips:
                        first_ns_ip = ns_ips[0]
                except Exception:
                    pass
            result["diagnostics"] = run_full_diagnostic(
                domain_to_check,
                authoritative_ns=first_ns_ip,
                custom_resolver=custom_resolver,
            )
        except Exception as e:
            warn_list.append(f"Warning: Diagnostic checks failed: {e}")

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

    # Diagnostics section (SOA, DNSSEC, TTL, PTR, auth-vs-recursive)
    diag = result.get("diagnostics")
    if diag:
        lines.append("\n--- Full DNS Diagnostic ---")
        lines.append(format_diagnostics_text(diag))

    # Propagation section
    prop = result.get("propagation")
    if prop:
        lines.append(format_propagation_text(prop, domain))

    # Trace section
    trace = result.get("trace")
    if trace:
        lines.append(format_trace_text(trace, domain))

    lines.append(f"\n--- Check Complete for: {domain} ---")
    return "\n".join(lines)


def format_propagation_text(data: Dict[str, Any], domain: str) -> str:
    """Formats propagation results as human-readable text."""
    lines = [f"\n--- DNS Propagation Check: {domain} ---"]
    resolvers = data.get("resolvers", {})
    consensus = data.get("consensus", {})

    for rtype in ["A", "AAAA", "NS", "MX"]:
        lines.append(f"\nRecord Type: {rtype}")
        for resolver_name, rdata in resolvers.items():
            entry = rdata.get(rtype, {})
            if entry.get("error"):
                records_str = f"Error - {entry['error'][:60]}"
                ttl_str = ""
            elif entry.get("records"):
                records_str = ", ".join(entry["records"])
                ttl_str = f"  [TTL: {entry.get('ttl', '?')}]"
            else:
                records_str = "No records"
                ttl_str = ""
            lines.append(f"  {resolver_name:<30}: {records_str}{ttl_str}")

        c = consensus.get(rtype, {})
        if c.get("agreed"):
            lines.append(f"  STATUS: ALL AGREE")
        elif c.get("mismatches"):
            diff_resolvers = ", ".join(m["resolver"] for m in c["mismatches"])
            lines.append(f"  STATUS: MISMATCH - {diff_resolvers} differ from consensus")

    summary = data.get("summary", "")
    if summary:
        lines.append(f"\nPropagation Summary: {summary}")

    return "\n".join(lines)


def format_trace_text(data: Dict[str, Any], domain: str) -> str:
    """Formats DNS trace results as human-readable text."""
    lines = [f"\n--- DNS Trace: {domain} ---"]

    if data.get("error"):
        lines.append(f"\nError: {data['error']}")
        return "\n".join(lines)

    steps = data.get("steps", [])
    for i, step in enumerate(steps, 1):
        level = step.get("level", "unknown").title()
        server = step.get("server_name", "unknown")
        ip = step.get("server_queried", "?")
        time_ms = step.get("response_time_ms", "?")
        aa_flag = " [AA]" if step.get("authoritative") else ""

        lines.append(f"\n[{i}] {level}: {server} ({ip}){aa_flag}    {time_ms}ms")

        if step.get("error"):
            lines.append(f"    Error: {step['error']}")
        elif step.get("answer"):
            answers = ", ".join(step["answer"])
            ttl = step.get("ttl", "?")
            lines.append(f"    -> Answer: {answers} [TTL: {ttl}]")
        elif step.get("ns_records"):
            ns_list = ", ".join(step["ns_records"][:4])
            if len(step["ns_records"]) > 4:
                ns_list += "..."
            lines.append(f"    -> Delegation: {ns_list}")

    chain = data.get("delegation_chain", "")
    total = data.get("total_time_ms", 0)
    lines.append(f"\nChain: {chain} | Total: {total}ms")

    return "\n".join(lines)


def format_diagnostics_text(data: Dict[str, Any]) -> str:
    """Formats diagnostic results (SOA, DNSSEC, TTL, PTR, auth-vs-recursive)."""
    lines = []

    # SOA
    soa = data.get("soa", {})
    if soa and not soa.get("error"):
        from dns_toolkit import format_ttl
        lines.append("\n=== SOA Record ===")
        lines.append(f"  Primary NS:   {soa.get('primary_ns', 'N/A')}")
        lines.append(f"  Admin Email:  {soa.get('admin_email', 'N/A')}")
        lines.append(f"  Serial:       {soa.get('serial', 'N/A')}")
        lines.append(f"  Refresh:      {format_ttl(soa['refresh']) if soa.get('refresh') else 'N/A'}")
        lines.append(f"  Retry:        {format_ttl(soa['retry']) if soa.get('retry') else 'N/A'}")
        lines.append(f"  Expire:       {format_ttl(soa['expire']) if soa.get('expire') else 'N/A'}")
        lines.append(f"  Minimum TTL:  {format_ttl(soa['minimum_ttl']) if soa.get('minimum_ttl') else 'N/A'}")
    elif soa and soa.get("error"):
        lines.append(f"\n=== SOA Record ===\n  Error: {soa['error']}")

    # DNSSEC
    dnssec = data.get("dnssec", {})
    if dnssec and not dnssec.get("error"):
        lines.append("\n=== DNSSEC ===")
        enabled = dnssec.get("enabled", False)
        valid = dnssec.get("valid")
        if enabled and valid:
            lines.append("  Status: ENABLED and VALID")
        elif enabled and valid is False:
            lines.append("  Status: ENABLED but VALIDATION FAILED")
        elif enabled:
            lines.append("  Status: ENABLED (validation inconclusive)")
        else:
            lines.append("  Status: NOT ENABLED")
        if dnssec.get("ds_records"):
            for ds in dnssec["ds_records"][:2]:
                lines.append(f"  DS: {ds[:70]}{'...' if len(ds) > 70 else ''}")
        if dnssec.get("note"):
            lines.append(f"  Note: {dnssec['note']}")
    elif dnssec and dnssec.get("error"):
        lines.append(f"\n=== DNSSEC ===\n  Error: {dnssec['error']}")

    # TTL Report
    ttl_report = data.get("ttl_report", {})
    if isinstance(ttl_report, dict) and not ttl_report.get("error"):
        if any(k in ttl_report for k in ["A", "AAAA", "NS", "MX", "SOA", "TXT"]):
            lines.append("\n=== TTL Report ===")
            for rtype in ["A", "AAAA", "NS", "MX", "SOA", "TXT"]:
                entry = ttl_report.get(rtype, {})
                note = entry.get("note", "N/A")
                lines.append(f"  {rtype:<6}: {note}")

    # Reverse DNS
    rev = data.get("reverse_dns", [])
    if rev:
        lines.append("\n=== Reverse DNS ===")
        for entry in rev:
            ip = entry.get("ip", "?")
            ptr = entry.get("ptr")
            error = entry.get("error")
            if ptr:
                lines.append(f"  {ip} -> {ptr}")
            elif error:
                lines.append(f"  {ip} -> {error}")

    # Auth vs Recursive
    avr = data.get("auth_vs_recursive", {})
    if avr and not avr.get("error"):
        auth_srv = avr.get("authoritative_server", "?")
        rec_srv = avr.get("recursive_server", "?")
        lines.append(f"\n=== Authoritative vs Recursive ===")
        lines.append(f"  Authoritative ({auth_srv}) vs Recursive ({rec_srv}):")
        for rtype in ["A", "MX"]:
            entry = avr.get(rtype, {})
            if entry.get("match"):
                auth_records = ", ".join(entry.get("authoritative", [])) or "none"
                lines.append(f"  {rtype:<4}: MATCH ({auth_records})")
            else:
                auth_records = ", ".join(entry.get("authoritative", [])) or "none"
                rec_records = ", ".join(entry.get("recursive", [])) or "none"
                lines.append(f"  {rtype:<4}: MISMATCH (auth: {auth_records} | rec: {rec_records})")
    elif avr and avr.get("error"):
        lines.append(f"\n=== Authoritative vs Recursive ===\n  {avr['error']}")

    return "\n".join(lines)


def results_to_json(results: List[Dict[str, Any]]) -> str:
    """Converts a list of domain results to a JSON string."""
    return json.dumps(results, indent=2, default=str)


def results_to_csv(results: List[Dict[str, Any]]) -> str:
    """Converts a list of domain results to CSV format with flattened fields."""
    output = io.StringIO()

    # Determine which optional sections are present
    has_mail = any(r.get('mail_authentication') for r in results)
    has_propagation = any(r.get('propagation') for r in results)
    has_trace = any(r.get('trace') for r in results)
    has_diagnostics = any(r.get('diagnostics') for r in results)

    fieldnames = [
        'domain', 'registrant', 'registrar', 'nameservers',
        'nameserver_error', 'dns_hosting_provider',
    ]
    if has_mail:
        fieldnames.extend(['dmarc_record', 'dmarc_error', 'spf_record', 'spf_error',
                           'dkim_selectors_found', 'dkim_error'])
    if has_propagation:
        fieldnames.extend(['propagation_summary', 'propagation_a_agreed',
                           'propagation_aaaa_agreed', 'propagation_ns_agreed',
                           'propagation_mx_agreed'])
    if has_trace:
        fieldnames.extend(['trace_chain', 'trace_total_ms'])
    if has_diagnostics:
        fieldnames.extend(['soa_serial', 'dnssec_enabled', 'dnssec_valid'])
    fieldnames.append('warnings')

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

        if has_mail:
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

        if has_propagation:
            prop = r.get('propagation')
            if prop:
                flat['propagation_summary'] = prop.get('summary', '')
                consensus = prop.get('consensus', {})
                for rtype in ['a', 'aaaa', 'ns', 'mx']:
                    c = consensus.get(rtype.upper(), {})
                    flat[f'propagation_{rtype}_agreed'] = str(c.get('agreed', ''))
            else:
                for field in ['propagation_summary', 'propagation_a_agreed',
                              'propagation_aaaa_agreed', 'propagation_ns_agreed',
                              'propagation_mx_agreed']:
                    flat[field] = ''

        if has_trace:
            trace = r.get('trace')
            if trace:
                flat['trace_chain'] = trace.get('delegation_chain', '')
                flat['trace_total_ms'] = str(trace.get('total_time_ms', ''))
            else:
                flat['trace_chain'] = ''
                flat['trace_total_ms'] = ''

        if has_diagnostics:
            diag = r.get('diagnostics')
            if diag:
                soa = diag.get('soa', {})
                flat['soa_serial'] = str(soa.get('serial', '')) if soa.get('serial') else ''
                dnssec = diag.get('dnssec', {})
                flat['dnssec_enabled'] = str(dnssec.get('enabled', ''))
                flat['dnssec_valid'] = str(dnssec.get('valid', ''))
            else:
                flat['soa_serial'] = ''
                flat['dnssec_enabled'] = ''
                flat['dnssec_valid'] = ''

        writer.writerow(flat)
    return output.getvalue()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="""
DomainPeek — CLI DNS Testing Toolkit.

Get DNS and WHOIS info for a domain using Python libraries.
Optionally check email authentication, DNS propagation, delegation
trace, and run full diagnostics.

Modes:
  (default)   Basic WHOIS + NS + DNS hosting provider
  -m          Email Authentication (SPF, DMARC, DKIM)
  -p          Propagation check across 8 public resolvers
  -t          DNS delegation trace (root -> TLD -> authoritative)
  -d          Full diagnostic (runs all of the above + SOA, DNSSEC,
              TTL report, reverse DNS, auth vs recursive comparison)

Bulk & Export:
  -b FILE     Check multiple domains from a CSV or JSON file
  -e FILE     Export results to .txt, .json, or .csv

Resolver Options:
  -r IP       Override the default resolver for standard queries
  -l IP       Include a local/internal resolver in propagation checks
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
    parser.add_argument(
        "-p", "--propagation",
        action="store_true",
        help="Check DNS propagation across 8 public resolvers (A, AAAA, NS, MX)."
    )
    parser.add_argument(
        "-t", "--trace",
        action="store_true",
        help="Trace DNS delegation chain from root servers to authoritative nameservers."
    )
    parser.add_argument(
        "-d", "--diagnose",
        action="store_true",
        help="Run full diagnostic (propagation, trace, mail auth, SOA, DNSSEC, TTL, PTR)."
    )
    parser.add_argument(
        "-l", "--local-resolver",
        metavar="IP",
        help="IP address of a local/internal DNS resolver to include in propagation checks."
    )
    parser.add_argument(
        "-r", "--resolver",
        metavar="IP",
        help="Override the default DNS resolver for standard queries."
    )
    args = parser.parse_args()

    # Diagnose mode auto-enables propagation, trace, and mail auth
    if args.diagnose:
        args.propagation = True
        args.trace = True
        args.mail_authentication = True

    # Local resolver implies propagation check
    if args.local_resolver and not args.propagation:
        args.propagation = True

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
        except PermissionError:
            print(f"Error: Permission denied reading '{args.bulk}'.", file=sys.stderr)
            sys.exit(1)
        except UnicodeDecodeError:
            print(f"Error: '{args.bulk}' is not a valid UTF-8 text file.", file=sys.stderr)
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

        result = check_domain(
            domain_input,
            check_mail=args.mail_authentication,
            check_propagation=args.propagation,
            check_trace=args.trace,
            check_diagnose=args.diagnose,
            local_resolver=args.local_resolver,
            custom_resolver=args.resolver,
        )
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
