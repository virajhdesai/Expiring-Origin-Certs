#!/usr/bin/env python3
import sys
import os
import ssl
import json
import socket
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import requests
from akamai.edgegrid import EdgeGridAuth, EdgeRc
from cryptography import x509
from cryptography.hazmat.primitives import hashes

def get_papi_session(section, edgerc_path="~/.edgerc", account_switch_key_cli=None):
    """
    Authenticate with Akamai PAPI via .edgerc using the specified section.
    Automatically extracts account_key or account_switch_key from the section.
    """
    expanded_path = os.path.expanduser(edgerc_path)
    if not os.path.isfile(expanded_path):
        print(f"[!] Error: .edgerc file not found at: {expanded_path}")
        sys.exit(1)

    rc = EdgeRc(expanded_path)
    if not rc.has_section(section):
        print(f"[!] Error: Section '[{section}]' does not exist in {expanded_path}")
        print(f"[*] Available sections: {rc.sections()}")
        sys.exit(1)

    session = requests.Session()
    session.auth = EdgeGridAuth.from_edgerc(rc, section)
    base_url = f"https://{rc.get(section, 'host')}"

    ask = account_switch_key_cli
    if not ask:
        for opt in ["account_key", "account_switch_key", "accountswitchkey"]:
            if rc.has_option(section, opt):
                ask = rc.get(section, opt)
                break

    if ask:
        print(f"[*] Loaded Account Switch Key from [{section}]: {ask}")
        session.params = {"accountSwitchKey": ask}

    return session, base_url

def find_property_direct_id(session, base_url, numeric_or_prp_id):
    """Attempt direct retrieval if user provided propertyId or ARL_ID_KEY."""
    prop_id = numeric_or_prp_id if str(numeric_or_prp_id).startswith("prp_") else f"prp_{numeric_or_prp_id}"
    url = f"{base_url}/papi/v1/properties/{prop_id}"
    res = session.get(url)
    if res.status_code == 200:
        data = res.json().get("properties", {}).get("items", [{}])[0]
        return (
            data.get("propertyId"),
            data.get("latestVersion"),
            data.get("productionVersion"),
            data.get("contractId"),
            data.get("groupId"),
            data.get("propertyName")
        )
    return None, None, None, None, None, None

def find_property_search(session, base_url, target_name):
    """Use find-by-value endpoint to locate property by name or hostname."""
    search_url = f"{base_url}/papi/v1/search/find-by-value"

    candidates = [
        target_name,
        target_name[:-3] if target_name.endswith("_pm") else target_name,
        f"{target_name}.edgesuite.net",
        f"{target_name}.edgekey.net"
    ]

    for query_val in candidates:
        for field in ["propertyName", "edgeHostname"]:
            try:
                res = session.post(search_url, json={field: query_val})
                if res.status_code == 200:
                    items = res.json().get("versions", {}).get("items", [])
                    if items:
                        item = items[0]
                        prop_id = item.get("propertyId")
                        contract_id = item.get("contractId")
                        group_id = item.get("groupId")
                        p_name = item.get("propertyName")
                        print(f"[*] Match found via search field '{field}' = '{query_val}' -> {p_name} ({prop_id})")
                        
                        sum_url = f"{base_url}/papi/v1/properties/{prop_id}?contractId={contract_id}&groupId={group_id}"
                        sum_res = session.get(sum_url)
                        latest_ver = None
                        prod_ver = None
                        if sum_res.status_code == 200:
                            props = sum_res.json().get("properties", {}).get("items", [{}])[0]
                            latest_ver = props.get("latestVersion")
                            prod_ver = props.get("productionVersion")

                        return prop_id, latest_ver, prod_ver, contract_id, group_id, p_name
            except Exception:
                pass
    return None, None, None, None, None, None

def find_property_comprehensive(session, base_url, target_identifier):
    """Comprehensive discovery: Direct ID -> Fast Search -> Full Group Scan."""
    target_clean = target_identifier.strip()

    digits_only = "".join(filter(str.isdigit, target_clean))
    if digits_only and (target_clean.isdigit() or target_clean.startswith("prp_")):
        print(f"[*] Trying direct Property ID lookup for '{target_clean}'...")
        prop_id, latest, prod, contract, grp, name = find_property_direct_id(session, base_url, target_clean)
        if prop_id:
            return prop_id, latest, prod, contract, grp, name

    print(f"[*] Searching via Property Manager Search API...")
    prop_id, latest, prod, contract, grp, name = find_property_search(session, base_url, target_clean)
    if prop_id:
        return prop_id, latest, prod, contract, grp, name

    target_no_pm = target_clean[:-3] if target_clean.endswith("_pm") else target_clean
    print("[*] Global search yielded no direct hit. Enumerating accessible groups...")
    
    groups_res = session.get(f"{base_url}/papi/v1/groups")
    if groups_res.status_code != 200:
        print(f"[!] Failed to list groups: HTTP {groups_res.status_code} - {groups_res.text}")
        return None, None, None, None, None, None

    groups_data = groups_res.json().get("groups", {}).get("items", [])
    print(f"[*] Accessible groups found: {len(groups_data)}. Scanning properties inside...")

    for i, grp in enumerate(groups_data, 1):
        group_id = grp.get("groupId")
        group_name = grp.get("groupName", "")
        contract_ids = grp.get("contractIds", [])

        for contract_id in contract_ids:
            props_url = f"{base_url}/papi/v1/properties"
            params = {"contractId": contract_id, "groupId": group_id}
            props_res = session.get(props_url, params=params)

            if props_res.status_code != 200:
                continue

            properties = props_res.json().get("properties", {}).get("items", [])
            print(f"    [{i}/{len(groups_data)}] Group: {group_name} ({group_id}) | Checked {len(properties)} properties...", end="\r")

            for prop in properties:
                p_name = prop.get("propertyName", "")
                p_id = prop.get("propertyId", "")

                if (p_name.lower() == target_clean.lower() or
                    p_name.lower() == target_no_pm.lower() or
                    p_id == target_clean or
                    p_id == f"prp_{target_clean}" or
                    target_no_pm.lower() in p_name.lower()):
                    
                    print(f"\n[*] Found match in group '{group_name}' -> Property: {p_name} ({p_id})")
                    return (
                        p_id,
                        prop.get("latestVersion"),
                        prop.get("productionVersion"),
                        contract_id,
                        group_id,
                        p_name
                    )

    print("\n")
    return None, None, None, None, None, None

def get_property_hostnames(session, base_url, property_id, version, contract_id=None, group_id=None):
    """Fetch assigned property hostnames."""
    url = f"{base_url}/papi/v1/properties/{property_id}/versions/{version}/hostnames"
    params = {}
    if contract_id:
        params["contractId"] = contract_id
    if group_id:
        params["groupId"] = group_id

    try:
        res = session.get(url, params=params)
        if res.status_code == 200:
            items = res.json().get("hostnames", {}).get("items", [])
            return [h.get("cnameFrom") for h in items if h.get("cnameFrom")]
    except Exception:
        pass
    return []

def select_best_default_incoming_hostname(assigned_hostnames, prop_name):
    """
    Selects the primary production hostname rather than picking an arbitrary
    failover or testing subdomain.
    """
    clean_prop = prop_name[:-3] if prop_name.endswith("_pm") else prop_name

    if clean_prop in assigned_hostnames:
        return clean_prop

    non_failover = [
        h for h in assigned_hostnames 
        if not any(h.startswith(prefix) for prefix in ["fail.", "dev.", "test.", "origin-", "origin."])
    ]
    if non_failover:
        for h in non_failover:
            if h == clean_prop or h == f"www.{clean_prop}":
                return h
        return non_failover[0]

    if assigned_hostnames:
        return assigned_hostnames[0]

    return clean_prop

def get_rule_tree(session, base_url, property_id, version, contract_id=None, group_id=None):
    """Retrieve the full JSON rule tree for a specific property version."""
    url = f"{base_url}/papi/v1/properties/{property_id}/versions/{version}/rules"
    params = {}
    if contract_id:
        params["contractId"] = contract_id
    if group_id:
        params["groupId"] = group_id

    res = session.get(
        url,
        params=params,
        headers={"Accept": "application/vnd.akamai.papirules.latest+json"}
    )
    res.raise_for_status()
    return res.json().get("rules", {})

def extract_hostname_from_criteria(rule):
    """Check if the rule contains a hostname criterion match."""
    for criterion in rule.get("criteria", []):
        crit_name = criterion.get("name", "")
        if crit_name in ["hostname", "requestHeader"]:
            options = criterion.get("options", {})
            values = options.get("values", [])
            if values:
                return values[0]
            val = options.get("value")
            if val:
                return val
    return None

def extract_origin_behaviors(rule, default_incoming_host, inherited_incoming_host=None, rule_path="Default"):
    """
    Recursively walk the rule tree to find every origin behavior and evaluate
    effective SNI using criteria and forward host header settings.
    """
    origins = []
    current_rule_name = rule.get("name", rule_path)

    rule_hostname_match = extract_hostname_from_criteria(rule)
    effective_incoming_host = rule_hostname_match or inherited_incoming_host or default_incoming_host

    for behavior in rule.get("behaviors", []):
        if behavior.get("name") == "origin":
            opt = behavior.get("options", {})
            origin_type = opt.get("originType", "CUSTOMER")
            origin_hostname = opt.get("hostname")
            forward_type = opt.get("forwardHostHeader", "REQUEST_HOST_HEADER")
            custom_forward = opt.get("customForwardHostHeader")

            if forward_type in ["REQUEST_HOST_HEADER", "INCOMING_HOST_HEADER"]:
                sni = effective_incoming_host
                header_reason = f"Incoming host header ({effective_incoming_host})"
            elif forward_type == "ORIGIN_HOSTNAME":
                sni = origin_hostname
                header_reason = f"Origin hostname ({origin_hostname})"
            elif forward_type == "CUSTOM":
                sni = custom_forward
                header_reason = f"Custom ({custom_forward})"
            else:
                sni = effective_incoming_host or origin_hostname
                header_reason = f"{forward_type} -> {sni}"

            origins.append({
                "rule_name": current_rule_name,
                "origin_type": origin_type,
                "hostname": origin_hostname,
                "forward_host_header_setting": forward_type,
                "resolved_sni": sni,
                "header_reason": header_reason
            })

    for child in rule.get("children", []):
        child_path = f"{current_rule_name} > {child.get('name', 'Unnamed Rule')}"
        origins.extend(
            extract_origin_behaviors(
                child,
                default_incoming_host=default_incoming_host,
                inherited_incoming_host=effective_incoming_host,
                rule_path=child_path
            )
        )

    return origins

def inspect_origin_leaf_cert(origin_hostname, sni_hostname, port=443, timeout=5):
    """
    Connects to origin_hostname:port with sni_hostname in TLS ClientHello
    and extracts the leaf certificate details, expiry, and SHA-1 fingerprint.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((origin_hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni_hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    return {"error": "Origin presented an empty TLS certificate"}

                cert = x509.load_der_x509_certificate(der_cert)
                sha1_hex = cert.fingerprint(hashes.SHA1()).hex()

                if hasattr(cert, "not_valid_after_utc"):
                    not_after = cert.not_valid_after_utc
                else:
                    not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

                days_left = (not_after - datetime.now(timezone.utc)).days

                return {
                    "subject": cert.subject.rfc4514_string(),
                    "expires_at": not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "days_remaining": days_left,
                    "sha1_fingerprint": ":".join(sha1_hex[i:i+2] for i in range(0, len(sha1_hex), 2)).upper(),
                    "sha1_raw": sha1_hex
                }
    except Exception as e:
        return {"error": str(e)}

def audit_single_origin(item, prop_name, prop_id, target_version, is_production, days_threshold):
    """Audits one origin behavior endpoint."""
    origin_host = item["hostname"]
    sni = item["resolved_sni"]

    if not origin_host or item["origin_type"] == "NET_STORAGE":
        return None

    cert_info = inspect_origin_leaf_cert(origin_host, sni)

    if "days_remaining" in cert_info and cert_info["days_remaining"] <= days_threshold:
        return {
            "property_name": prop_name,
            "property_id": prop_id,
            "property_version": target_version,
            "is_production": is_production,
            "rule_location": item["rule_name"],
            "origin_hostname": origin_host,
            "forward_host_setting": item["forward_host_header_setting"],
            "sni_used": sni,
            "sni_selection_reason": item["header_reason"],
            "cert_subject": cert_info["subject"],
            "expires_at": cert_info["expires_at"],
            "days_remaining": cert_info["days_remaining"],
            "sha1_fingerprint": cert_info["sha1_fingerprint"],
            "sha1_raw": cert_info["sha1_raw"],
            "inspected_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        }
    return None

def main():
    parser = argparse.ArgumentParser(
        description="Audit origin server certificates for an Akamai Property expiring within threshold and save to JSON."
    )
    parser.add_argument(
        "-p", "--property",
        required=True,
        help="Property name or Property ID / ARL_ID"
    )
    parser.add_argument(
        "-s", "--section",
        required=True,
        help="Section name in .edgerc (e.g. akamaib)"
    )
    parser.add_argument(
        "-v", "--version",
        type=int,
        help="Property version number (defaults to active Production version)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Custom output JSON file path (default: expiring_origin_certs_<property_name>.json)"
    )
    parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Alert threshold in days (default: 30)"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=6,
        help="Number of concurrent worker threads (default: 6)"
    )
    parser.add_argument(
        "--incoming-host",
        help="Explicit incoming hostname override for SNI when REQUEST_HOST_HEADER is used (optional)"
    )
    parser.add_argument(
        "--account-switch-key",
        help="Explicit Akamai Account Switch Key override (optional, defaults to reading account_key from .edgerc)"
    )
    parser.add_argument(
        "--edgerc",
        default="~/.edgerc",
        help="Path to .edgerc config file (default: ~/.edgerc)"
    )
    args = parser.parse_args()

    print(f"[*] Initializing session with .edgerc section: [{args.section}]")
    session, base_url = get_papi_session(section=args.section, edgerc_path=args.edgerc, account_switch_key_cli=args.account_switch_key)

    print(f"[*] Resolving property identifier: {args.property}")
    prop_id, latest_ver, prod_ver, contract_id, group_id, prop_name = find_property_comprehensive(
        session, base_url, args.property
    )

    if not prop_id:
        print(f"[!] Unable to locate property '{args.property}' within accessible groups and contracts for section [{args.section}].")
        sys.exit(1)

    target_version = args.version or prod_ver or latest_ver
    is_prod = target_version == prod_ver
    print(f"[*] Found Property: {prop_name} (ID: {prop_id}, Contract: {contract_id}, Group: {group_id})")
    print(f"[*] Fetching rules for Version: {target_version} {'(Production)' if is_prod else ''}")

    # Determine default incoming host
    assigned_hostnames = get_property_hostnames(session, base_url, prop_id, target_version, contract_id, group_id)
    if args.incoming_host:
        default_incoming_host = args.incoming_host
    else:
        default_incoming_host = select_best_default_incoming_hostname(assigned_hostnames, prop_name)

    print(f"[*] Selected Default Incoming Hostname: {default_incoming_host}")

    rule_tree = get_rule_tree(session, base_url, prop_id, target_version, contract_id, group_id)
    origin_configs = extract_origin_behaviors(rule_tree, default_incoming_host=default_incoming_host)

    # Filter out empty or NetStorage origins
    valid_origins = [o for o in origin_configs if o["hostname"] and o["origin_type"] != "NET_STORAGE"]
    total_origins = len(valid_origins)

    clean_file_prop = prop_name.replace("/", "_").replace("\\", "_")
    output_file = args.output or f"expiring_origin_certs_{clean_file_prop}.json"

    print(f"[*] Found {total_origins} network origin behavior(s).")
    print(f"[*] Auditing with {args.threads} parallel threads (Threshold: <= {args.days} days)...\n")

    expiring_records = []
    completed_count = 0
    lock = threading.Lock()

    # Deduplicate origin + SNI pairs to avoid redundant TLS handshakes
    unique_items = []
    seen_pairs = set()
    for item in valid_origins:
        pair = (item["hostname"], item["resolved_sni"])
        if pair not in seen_pairs:
            seen_pairs.add(pair)
            unique_items.append(item)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(
                audit_single_origin,
                item,
                prop_name,
                prop_id,
                target_version,
                is_prod,
                args.days
            )
            for item in unique_items
        ]

        for future in as_completed(futures):
            res = future.result()
            with lock:
                completed_count += 1
                if res:
                    expiring_records.append(res)
                
                # Fixed-width formatting prevents garbled text in PowerShell
                line = f"[{completed_count}/{len(unique_items)}] Audited Origins | Expiring Found: {len(expiring_records)}"
                sys.stdout.write(f"\r{line:<80}")
                sys.stdout.flush()

    sys.stdout.write("\r" + " " * 82 + "\r")
    sys.stdout.flush()

    # Save to JSON file
    payload = {
        "metadata": {
            "property_name": prop_name,
            "property_id": prop_id,
            "property_version": target_version,
            "is_production": is_prod,
            "contract_id": contract_id,
            "group_id": group_id,
            "section": args.section,
            "threshold_days": args.days,
            "total_origins_inspected": len(unique_items),
            "total_expiring_origins": len(expiring_records),
            "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        },
        "expiring_certificates": expiring_records
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print("=" * 85)
    print(f"[*] Audit Complete for Property: {prop_name}")
    print(f"[*] Total Origins Audited  : {len(unique_items)}")
    print(f"[*] Expiring Certificates  : {len(expiring_records)}")
    print(f"[*] Results Saved To File  : {os.path.abspath(output_file)}")
    print("=" * 85)

if __name__ == "__main__":
    main()