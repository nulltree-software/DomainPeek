#!/usr/bin/env python3
import argparse
import sys
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
def get_whois_info(domain: str) -> Optional[Any]:
    """Performs a WHOIS lookup for the domain and handles common errors."""
    try:
        # timeout parameter might not be supported by all underlying whois libs/servers
        # The default whois library might follow redirects, which can be slow.
        return whois.whois(domain)
    except whois.exceptions.UnknownTld:
        print(f"Warning: WHOIS lookup failed for '{domain}'. Unknown TLD.")
        return None
    except whois.exceptions.WhoisCommandFailed as e:
        print(f"Warning: WHOIS command execution failed for '{domain}': {e}")
        return None
    except whois.exceptions.PywhoisError as e: # General catch-all for the library
        print(f"Warning: WHOIS lookup error for '{domain}': {e}")
        return None
    except socket.timeout:
        print(f"Warning: WHOIS lookup for '{domain}' timed out.")
        return None
    except Exception as e: # Catch any other unexpected errors
        print(f"Warning: An unexpected error occurred during WHOIS lookup for '{domain}': {e}")
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
def get_registrable_domain(fqdn: str) -> Optional[str]:
    """
    Extracts the registrable domain (e.g., example.com, example.co.uk)
    from a fully qualified domain name (e.g., ns1.example.com) using tldextract.
    """
    if not fqdn:
        return None
    try:
        ext = tldextract.extract(fqdn, include_psl_private_domains=True)
        if ext.registered_domain:
             return ext.registered_domain
        else:
            print(f"Warning: Could not extract registrable domain from '{fqdn}'")
            return None
    except Exception as e:
        print(f"Error using tldextract on {fqdn}: {e}")
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


def main():
    parser = argparse.ArgumentParser(
        description="""
Get DNS and WHOIS info for a domain using Python libraries.
Optionally check common email authentication records (SPF, DMARC, DKIM).

Outputs basic info by default. Use -m for Email Authentication checks.

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
    parser.add_argument("domain", help="The domain name to check (e.g., example.com)")
    parser.add_argument(
        "-m", "--mail-authentication",
        action="store_true", # Set to True if flag is present
        help="Check for SPF, DMARC and DKIM records."
    )
    args = parser.parse_args()
    domain_to_check = args.domain.lower().strip() # Normalize domain

    print(f"--- Checking Domain: {domain_to_check} ---\n")

    # Get Domain Registrant & Registrar via WHOIS
    domain_whois = get_whois_info(domain_to_check)

    registrant = "Not Found"
    registrar = "Not Found"

    if domain_whois:
        # Try common attributes for registrant name/org
        registrant_name = get_primary_whois_value(domain_whois.get('name') or domain_whois.get('registrant_name'))
        registrant_org = get_primary_whois_value(domain_whois.get('org') or domain_whois.get('registrant_organization'))

        if registrant_name != "Not Found":
            registrant = registrant_name
        elif registrant_org != "Not Found":
             registrant = registrant_org # Use Org if name not found
        else:
             registrant = "Not Found" # Explicitly state if neither found

        # Registrar is usually more consistent
        registrar = get_primary_whois_value(domain_whois.get('registrar'))
        # Fallback
        if registrar == "Not Found":
            url = get_primary_whois_value(domain_whois.get('registrar_url'))
            if url != "Not Found":
                registrar = f"URL: {url}"

    else:
        registrant = "WHOIS Lookup Failed"
        registrar = "WHOIS Lookup Failed"

    print(f"Domain Registrant: {registrant}")
    print(f"Domain Registrar: {registrar}")

    # Get Nameservers (NS Records) via DNS
    nameservers, ns_error_msg = get_dns_records(domain_to_check, 'NS')

    first_nameserver = None
    if ns_error_msg:
        print(f"Error: {ns_error_msg}")
    elif nameservers:
        print(f"Nameservers: {', '.join(nameservers)}")
        first_nameserver = nameservers[0]
    else:
        # Should be covered by error msg, but just in case
        print("No nameservers identified.")


    # Get Registrar of the Nameserver's Owner Domain via WHOIS
    # This helps identify the hosting provider (often the registrar of the NS domain)
    dns_hosting_provider = "Not Found / Unable to Determine" # Default value

    # Set state for cases where Nameservers include the DNS Hosting Provider but the Nameserver's Registrar is different
    # E.G. ns1.microsoftonline.com shows MarkMonitor Inc as the Registrar but Microsoft Azure DNS / M365 is the DNS Management Platform
    provider_detected = False

    if first_nameserver:
        ns_lower = first_nameserver.lower()

        # Check known provider patterns using the dictionary
        for pattern, provider_name in KNOWN_PROVIDER_PATTERNS.items():
            if pattern in ns_lower:
                dns_hosting_provider = provider_name # Assign the detected provider name
                provider_detected = True
                break # Found a match, no need to check further patterns

        # If no known pattern matched, fallback to WHOIS inference
        if not provider_detected:
            ns_owner_domain = get_registrable_domain(first_nameserver)
            if ns_owner_domain:
                ns_domain_whois = get_whois_info(ns_owner_domain)
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

    print(f"DNS Hosting Provider: {dns_hosting_provider}")

    if args.mail_authentication:
        print("\n--- Email Authentication ---")

        # DMARC Check
        dmarc_domain = f"_dmarc.{domain_to_check}"
        dmarc_records, dmarc_error = get_dns_records(dmarc_domain, 'TXT')
        if dmarc_error and not dmarc_records: print(f"\nDMARC ({dmarc_domain}): \nError - {dmarc_error}")
        elif dmarc_records: print(f"\nDMARC ({dmarc_domain}): \n{dmarc_records[0]}") # Display first DMARC found
        else: print(f"\nDMARC ({dmarc_domain}): \nNot Found")

        # SPF Check using helper function
        spf_record, spf_error = check_spf(domain_to_check)
        if spf_error: print(f"\nSPF ({domain_to_check}): \nError - {spf_error}")
        elif spf_record: print(f"\nSPF ({domain_to_check}): \n{spf_record}")
        else: print(f"\nSPF ({domain_to_check}): \nNot Found")

        # DKIM Check (Using Common Selectors)
        found_dkim, dkim_general_error = check_common_dkim(domain_to_check)
        if dkim_general_error:
            print(f"\nDKIM: \n{dkim_general_error}") # Report general lookup errors if any
        if found_dkim:
            print("\nDKIM:")
            for selector, records in found_dkim.items():
                for record in records:
                    print(f"Selector '{selector}': {record[:80]}{'...' if len(record) > 80 else ''}") # Truncate long keys
        elif not dkim_general_error: # Only print 'not found' if there wasn't a general error
            print("\nDKIM: \nNo records found using common selectors.")
        print("\n(Note: This only checks common selectors, others may exist.)")

    print(f"\n--- Check Complete for: {domain_to_check} ---")

if __name__ == "__main__":
    main()
