#!/usr/bin/env python3
"""
DNS Toolkit — Advanced DNS testing functions for DomainPeek.

Provides propagation checking, DNS trace, and full diagnostic capabilities.
"""
import time
import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import dns.flags
import dns.name
import dns.reversename
import dns.dnssec
import dns.rdataclass
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Any, Tuple

# Import constants and helpers from domainpeek
from domainpeek import PUBLIC_RESOLVERS, ROOT_SERVERS, get_dns_records


# --- Utility ---

def format_ttl(seconds: int) -> str:
    """Convert TTL seconds to human-readable string."""
    if seconds >= 86400:
        count = seconds // 86400
        return f"{seconds} ({count} day{'s' if count != 1 else ''})"
    elif seconds >= 3600:
        count = seconds // 3600
        return f"{seconds} ({count} hour{'s' if count != 1 else ''})"
    elif seconds >= 60:
        count = seconds // 60
        return f"{seconds} ({count} minute{'s' if count != 1 else ''})"
    else:
        return f"{seconds} ({seconds} second{'s' if seconds != 1 else ''})"


# --- Propagation Check ---

def query_resolver(domain: str, record_type: str, resolver_ip: str,
                   timeout: float = 5.0) -> Dict[str, Any]:
    """
    Query a single resolver for a single record type.
    Returns: {"records": [...], "ttl": int|None, "error": str|None}
    """
    records, error, ttl = get_dns_records(domain, record_type,
                                          nameserver=resolver_ip, timeout=timeout)
    return {"records": sorted(records), "ttl": ttl, "error": error}


def compute_consensus(resolver_results: Dict[str, Dict[str, Any]],
                      record_types: List[str]) -> Dict[str, Any]:
    """
    Analyze results across resolvers to determine majority agreement per record type.
    """
    consensus: Dict[str, Any] = {}

    for rtype in record_types:
        # Collect record sets from each resolver (skip errors)
        record_sets: Dict[str, List[str]] = {}
        for resolver_name, data in resolver_results.items():
            rdata = data.get(rtype, {})
            if rdata.get("records"):
                # Use frozenset of sorted records as key for comparison
                record_sets[resolver_name] = rdata["records"]

        if not record_sets:
            consensus[rtype] = {
                "agreed": True,
                "canonical": [],
                "mismatches": [],
            }
            continue

        # Find majority: count how many resolvers have each unique record set
        set_counts: Dict[tuple, int] = {}
        set_to_resolvers: Dict[tuple, List[str]] = {}
        for resolver_name, records in record_sets.items():
            key = tuple(sorted(records))
            set_counts[key] = set_counts.get(key, 0) + 1
            set_to_resolvers.setdefault(key, []).append(resolver_name)

        # The canonical set is the one held by the most resolvers
        canonical_key = max(set_counts, key=set_counts.get)
        canonical_records = list(canonical_key)

        # Find mismatches
        mismatches = []
        for key, resolvers in set_to_resolvers.items():
            if key != canonical_key:
                for r in resolvers:
                    mismatches.append({
                        "resolver": r,
                        "records": list(key),
                    })

        consensus[rtype] = {
            "agreed": len(mismatches) == 0,
            "canonical": canonical_records,
            "mismatches": mismatches,
        }

    return consensus


def run_propagation_check(domain: str,
                          local_resolver: Optional[str] = None) -> Dict[str, Any]:
    """
    Query A, AAAA, NS, MX across all public resolvers (and local if provided).
    Uses ThreadPoolExecutor for parallel queries.
    """
    resolvers: Dict[str, str] = dict(PUBLIC_RESOLVERS)
    if local_resolver:
        resolvers[f"Local ({local_resolver})"] = local_resolver

    record_types = ["A", "AAAA", "NS", "MX"]
    resolver_results: Dict[str, Dict[str, Any]] = {}

    # Initialize result structure
    for name, ip in resolvers.items():
        resolver_results[name] = {"ip": ip}

    # Query all resolvers x record types in parallel
    with ThreadPoolExecutor(max_workers=16) as executor:
        future_map: Dict[Any, Tuple[str, str]] = {}
        for name, ip in resolvers.items():
            for rtype in record_types:
                future = executor.submit(query_resolver, domain, rtype, ip)
                future_map[future] = (name, rtype)

        for future in as_completed(future_map):
            name, rtype = future_map[future]
            try:
                resolver_results[name][rtype] = future.result()
            except Exception as e:
                resolver_results[name][rtype] = {
                    "records": [], "ttl": None, "error": str(e)
                }

    consensus = compute_consensus(resolver_results, record_types)

    # Build summary
    total_types = len(record_types)
    agreed_types = sum(1 for c in consensus.values() if c["agreed"])
    total_resolvers = len(resolvers)

    if agreed_types == total_types:
        summary = f"All {total_resolvers} resolvers agree on all {total_types} record types."
    else:
        mismatched_types = [rt for rt in record_types if not consensus[rt]["agreed"]]
        summary = (f"{agreed_types}/{total_types} record types consistent. "
                   f"Mismatches on: {', '.join(mismatched_types)}.")

    return {
        "resolvers": resolver_results,
        "consensus": consensus,
        "summary": summary,
    }


# --- DNS Trace ---

def _level_name(depth: int) -> str:
    """Return a human-readable name for the delegation level."""
    if depth == 0:
        return "root"
    elif depth == 1:
        return "tld"
    else:
        return "authoritative"


def query_nameserver_direct(qname: str, rdtype: str, nameserver_ip: str,
                            timeout: float = 5.0) -> dns.message.Message:
    """
    Send a non-recursive query to a specific nameserver via UDP.
    Falls back to TCP if the response is truncated.
    """
    query = dns.message.make_query(dns.name.from_text(qname), dns.rdatatype.from_text(rdtype))
    query.flags &= ~dns.flags.RD  # Non-recursive

    response = dns.query.udp(query, nameserver_ip, timeout=timeout)

    # TCP fallback for truncated responses
    if response.flags & dns.flags.TC:
        response = dns.query.tcp(query, nameserver_ip, timeout=timeout)

    return response


def dns_trace(domain: str, record_type: str = "A") -> Dict[str, Any]:
    """
    Perform iterative DNS resolution from root servers to authoritative nameservers.
    Returns a dict with steps, delegation chain, and timing.
    """
    steps: List[Dict[str, Any]] = []
    max_depth = 10

    # Start with a root server — try multiple if the first fails
    current_server_ip = None
    current_server_name = None
    for name, ip in ROOT_SERVERS:
        try:
            # Quick connectivity test
            test_query = dns.message.make_query(dns.name.from_text(domain),
                                                dns.rdatatype.from_text(record_type))
            test_query.flags &= ~dns.flags.RD
            dns.query.udp(test_query, ip, timeout=3.0)
            current_server_ip = ip
            current_server_name = name
            break
        except Exception:
            continue

    if not current_server_ip:
        return {
            "steps": [],
            "delegation_chain": "Failed to reach any root server",
            "total_time_ms": 0,
            "error": "Could not connect to any root server.",
        }

    # Actually trace now (re-query since the test was just for connectivity)
    for depth in range(max_depth):
        start_time = time.monotonic()
        step: Dict[str, Any] = {
            "level": _level_name(depth),
            "server_name": current_server_name,
            "server_queried": current_server_ip,
            "query": f"{domain} {record_type}",
            "response_time_ms": None,
        }

        try:
            response = query_nameserver_direct(domain, record_type, current_server_ip)
        except dns.exception.Timeout:
            step["error"] = f"Timeout querying {current_server_ip}"
            step["response_time_ms"] = round((time.monotonic() - start_time) * 1000, 1)
            steps.append(step)
            break
        except Exception as e:
            step["error"] = f"Error querying {current_server_ip}: {e}"
            step["response_time_ms"] = round((time.monotonic() - start_time) * 1000, 1)
            steps.append(step)
            break

        elapsed_ms = round((time.monotonic() - start_time) * 1000, 1)
        step["response_time_ms"] = elapsed_ms

        # Check for answer
        if response.answer:
            answers = []
            ttl = None
            for rrset in response.answer:
                if ttl is None:
                    ttl = rrset.ttl
                for rr in rrset:
                    answers.append(rr.to_text().rstrip('.'))
            step["answer"] = answers
            step["ttl"] = ttl
            step["authoritative"] = bool(response.flags & dns.flags.AA)
            steps.append(step)
            break

        # Check for delegation (NS in authority section)
        ns_records = []
        glue_records: Dict[str, str] = {}

        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NS:
                for rr in rrset:
                    ns_name = rr.to_text().rstrip('.')
                    ns_records.append(ns_name)

        for rrset in response.additional:
            if rrset.rdtype == dns.rdatatype.A:
                name = rrset.name.to_text().rstrip('.')
                glue_records[name] = rrset[0].to_text()

        step["ns_records"] = ns_records
        step["glue_records"] = glue_records
        steps.append(step)

        if not ns_records:
            break  # No delegation and no answer — dead end

        # Pick next server: prefer one with a glue record
        next_ip = None
        next_name = None
        for ns in ns_records:
            if ns in glue_records:
                next_ip = glue_records[ns]
                next_name = ns
                break

        if not next_ip:
            # No glue — resolve the first NS name using system resolver
            try:
                resolved = dns.resolver.resolve(ns_records[0], 'A')
                next_ip = resolved[0].to_text()
                next_name = ns_records[0]
            except Exception:
                break

        current_server_ip = next_ip
        current_server_name = next_name

    # Build delegation chain string
    chain_parts: List[str] = []
    for s in steps:
        label = s.get("server_name", "unknown")
        if s["level"] == "root":
            chain_parts.append("root")
        else:
            chain_parts.append(label)

    total_time = sum(s.get("response_time_ms", 0) or 0 for s in steps)

    return {
        "steps": steps,
        "delegation_chain": " -> ".join(chain_parts) if chain_parts else "No delegation chain",
        "total_time_ms": round(total_time, 1),
    }


# --- Diagnostic Functions ---

def check_soa(domain: str, nameserver: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve and parse the SOA record for a domain."""
    result: Dict[str, Any] = {
        "primary_ns": None, "admin_email": None, "serial": None,
        "refresh": None, "retry": None, "expire": None,
        "minimum_ttl": None, "error": None,
    }
    try:
        resolver = dns.resolver.Resolver()
        if nameserver:
            resolver.nameservers = [nameserver]
        resolver.lifetime = 5.0
        answer = resolver.resolve(domain, 'SOA')
        if answer.rrset:
            soa = answer.rrset[0]
            result["primary_ns"] = soa.mname.to_text().rstrip('.')
            # Convert admin email from DNS format (admin.example.com -> admin@example.com)
            admin = soa.rname.to_text().rstrip('.')
            parts = admin.split('.', 1)
            result["admin_email"] = f"{parts[0]}@{parts[1]}" if len(parts) == 2 else admin
            result["serial"] = soa.serial
            result["refresh"] = soa.refresh
            result["retry"] = soa.retry
            result["expire"] = soa.expire
            result["minimum_ttl"] = soa.minimum
    except Exception as e:
        result["error"] = str(e)
    return result


def check_dnssec(domain: str) -> Dict[str, Any]:
    """
    Check DNSSEC status for a domain.
    Queries DS records at parent and DNSKEY at the domain.
    """
    result: Dict[str, Any] = {
        "enabled": False, "valid": None, "ds_records": [],
        "dnskey_records": [], "error": None, "note": "",
    }
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0

        # Check for DS records (delegated signing)
        try:
            ds_answer = resolver.resolve(domain, 'DS')
            if ds_answer.rrset:
                result["ds_records"] = [rr.to_text() for rr in ds_answer.rrset]
                result["enabled"] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.resolver.NoNameservers:
            result["note"] = "Could not reach nameservers for DS lookup."

        # Check for DNSKEY records
        try:
            dnskey_answer = resolver.resolve(domain, 'DNSKEY')
            if dnskey_answer.rrset:
                dnskey_texts: List[str] = []
                for rr in dnskey_answer.rrset:
                    text = rr.to_text()
                    dnskey_texts.append(text[:80] + "..." if len(text) > 80 else text)
                result["dnskey_records"] = dnskey_texts
                if not result["enabled"]:
                    result["enabled"] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass

        # Attempt validation if we have both DS and DNSKEY
        if result["ds_records"] and result["dnskey_records"]:
            try:
                # Query with DNSSEC OK flag
                resolver.use_edns(edns=0, ednsflags=dns.flags.DO, payload=4096)
                dnskey_resp = resolver.resolve(domain, 'DNSKEY')
                if dnskey_resp.response.answer:
                    # Check for RRSIG presence as a basic validation indicator
                    has_rrsig = any(
                        rrset.rdtype == dns.rdatatype.RRSIG
                        for rrset in dnskey_resp.response.answer
                    )
                    if has_rrsig:
                        result["valid"] = True
                        result["note"] = "DNSSEC is enabled. RRSIG records present."
                    else:
                        result["valid"] = False
                        result["note"] = "DNSSEC keys found but no RRSIG in response."
            except Exception as e:
                result["valid"] = False
                result["note"] = f"DNSSEC validation check encountered an error: {e}"
        elif result["enabled"]:
            result["note"] = "DNSSEC keys found but validation could not be fully verified."
        else:
            result["note"] = "DNSSEC is not enabled for this domain."

    except Exception as e:
        result["error"] = str(e)

    return result


def check_ttl_report(domain: str, nameserver: Optional[str] = None) -> Dict[str, Any]:
    """Query common record types and report TTL for each."""
    report: Dict[str, Any] = {}
    record_types = ["A", "AAAA", "NS", "MX", "SOA", "TXT"]

    for rtype in record_types:
        records, error, ttl = get_dns_records(domain, rtype, nameserver=nameserver)
        if ttl is not None:
            report[rtype] = {"ttl": ttl, "note": format_ttl(ttl)}
        elif error:
            report[rtype] = {"ttl": None, "note": f"No record ({error.split('.')[0]})"}
        else:
            report[rtype] = {"ttl": None, "note": "No record found"}

    return report


def check_reverse_dns(ip_addresses: List[str]) -> List[Dict[str, Any]]:
    """Perform PTR lookups for a list of IP addresses."""
    results: List[Dict[str, Any]] = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0

    for ip in ip_addresses:
        entry: Dict[str, Any] = {"ip": ip, "ptr": None, "error": None}
        try:
            rev_name = dns.reversename.from_address(ip)
            answer = resolver.resolve(rev_name, 'PTR')
            if answer.rrset:
                entry["ptr"] = answer.rrset[0].to_text().rstrip('.')
        except dns.resolver.NXDOMAIN:
            entry["error"] = "No PTR record"
        except dns.resolver.NoAnswer:
            entry["error"] = "No PTR record"
        except dns.resolver.NoNameservers:
            entry["error"] = "No reachable nameservers for PTR lookup"
        except dns.resolver.Timeout:
            entry["error"] = "Timeout"
        except Exception as e:
            entry["error"] = str(e)
        results.append(entry)

    return results


def check_auth_vs_recursive(domain: str, auth_ns_ip: str,
                            recursive: str = "8.8.8.8") -> Dict[str, Any]:
    """Compare A and MX records from authoritative vs recursive resolver."""
    result: Dict[str, Any] = {
        "authoritative_server": auth_ns_ip,
        "recursive_server": recursive,
    }

    for rtype in ["A", "MX"]:
        auth_records, auth_error, _ = get_dns_records(domain, rtype,
                                                      nameserver=auth_ns_ip, timeout=5.0)
        rec_records, rec_error, _ = get_dns_records(domain, rtype,
                                                    nameserver=recursive, timeout=5.0)

        auth_set = set(sorted(auth_records)) if auth_records else set()
        rec_set = set(sorted(rec_records)) if rec_records else set()

        result[rtype] = {
            "authoritative": sorted(auth_records) if auth_records else [],
            "recursive": sorted(rec_records) if rec_records else [],
            "match": auth_set == rec_set,
            "auth_error": auth_error,
            "rec_error": rec_error,
        }

    return result


def run_full_diagnostic(domain: str,
                        authoritative_ns: Optional[str] = None,
                        custom_resolver: Optional[str] = None) -> Dict[str, Any]:
    """
    Orchestrator for full diagnostic mode.
    Runs SOA, DNSSEC, TTL report, reverse DNS, and auth-vs-recursive checks.
    """
    diagnostics: Dict[str, Any] = {}

    # SOA
    try:
        diagnostics["soa"] = check_soa(domain, nameserver=custom_resolver)
    except Exception as e:
        diagnostics["soa"] = {"error": str(e)}

    # DNSSEC
    try:
        diagnostics["dnssec"] = check_dnssec(domain)
    except Exception as e:
        diagnostics["dnssec"] = {"error": str(e)}

    # TTL Report
    try:
        diagnostics["ttl_report"] = check_ttl_report(domain, nameserver=custom_resolver)
    except Exception as e:
        diagnostics["ttl_report"] = {"error": str(e)}

    # Reverse DNS — get A records first, then do PTR lookups
    try:
        a_records, _, _ = get_dns_records(domain, 'A', nameserver=custom_resolver)
        if a_records:
            diagnostics["reverse_dns"] = check_reverse_dns(a_records)
        else:
            diagnostics["reverse_dns"] = []
    except Exception as e:
        diagnostics["reverse_dns"] = [{"error": str(e)}]

    # Auth vs Recursive
    if authoritative_ns:
        try:
            diagnostics["auth_vs_recursive"] = check_auth_vs_recursive(
                domain, authoritative_ns
            )
        except Exception as e:
            diagnostics["auth_vs_recursive"] = {"error": str(e)}
    else:
        diagnostics["auth_vs_recursive"] = {
            "error": "Could not determine authoritative nameserver IP."
        }

    return diagnostics
