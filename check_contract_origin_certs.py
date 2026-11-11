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

def get_groups_for_contract(session, base_url, target_contract_id):
    """Find all groupIds that have access to the target contract."""
    groups_res = session.get(f"{base_url}/papi/v1/groups")
    if groups_res.status_code != 200:
        print(f"[!] Failed to list groups: HTTP {groups_res.status_code} - {groups_res.text}")
        return []

    clean_cid = target_contract_id if target_contract_id.startswith("ctr_") else f"ctr_{target_contract_id}"
    matched_group_ids = []

    for grp in groups_res.json().get("groups", {}).get("items", []):
        cids = grp.get("contractIds", [])
        if clean_cid in cids:
            matched_group_ids.append(grp.get("groupId"))

    return matched_group_ids

def get_properties_for_contract(session, base_url, target_contract_id):
    """Retrieve all unique properties belonging to the specified contract."""
    clean_cid = target_contract_id if target_contract_id.startswith("ctr_") else f"ctr_{target_contract_id}"
    group_ids = get_groups_for_contract(session, base_url, clean_cid)

    if not group_ids:
        print(f"[!] No groups found associated with contract '{clean_cid}'.")
        return []

    print(f"[*] Found {len(group_ids)} group(s) under contract {clean_cid}. Fetching property inventory...")
    properties_by_id = {}

    for gid in group_ids:
        props_url = f"{base_url}/papi/v1/properties"
        params = {"contractId": clean_cid, "groupId": gid}
        res = session.get(props_url, params=params)
        if res.status_code == 200:
            for prop in res.json().get("properties", {}).get("items", []):
                pid = prop.get("propertyId")
                if pid and pid not in properties_by_id:
                    properties_by_id[pid] = {
                        "propertyId": pid,
                        "propertyName": prop.get("propertyName"),
                        "groupId": gid,
                        "contractId": clean_cid,
                        "productionVersion": prop.get("productionVersion"),
                        "latestVersion": prop.get("latestVersion")
                    }

    return list(properties_by_id.values())

def get_property_hostnames(session, base_url, property_id, version, contract_id, group_id):
    """Fetch assigned edge hostnames for a property version."""
    url = f"{base_url}/papi/v1/properties/{property_id}/versions/{version}/hostnames"
    params = {"contractId": contract_id, "groupId": group_id}
    try:
        res = session.get(url, params=params)
        if res.status_code == 200:
            items = res.json().get("hostnames", {}).get("items", [])
            return [h.get("cnameFrom") for h in items if h.get("cnameFrom")]
    except Exception:
        pass
    return []

def select_best_default_incoming_hostname(assigned_hostnames, prop_name):
    """Select the primary production hostname rather than picking an arbitrary failover hostname."""
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

def get_rule_tree(session, base_url, property_id, version, contract_id, group_id):
    """Retrieve the full JSON rule tree for a specific property version."""
    url = f"{base_url}/papi/v1/properties/{property_id}/versions/{version}/rules"
    params = {"contractId": contract_id, "groupId": group_id}
    res = session.get(
        url,
        params=params,
        headers={"Accept": "application/vnd.akamai.papirules.latest+json"}
    )
    res.raise_for_status()
    return res.json().get("rules", {})

def extract_hostname_from_criteria(rule):
    """Extract any hostname match values configured in the rule's criteria."""
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
    """Recursively walk the rule tree to find every origin behavior."""
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
    """Connect to origin_hostname:port with sni_hostname and inspect the leaf certificate."""
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

def audit_single_property(prop, session, base_url, clean_contract_id, days_threshold):
    """Audits all origin behaviors for a single property configuration."""
    prop_name = prop["propertyName"]
    prop_id = prop["propertyId"]
    group_id = prop["groupId"]
    prod_ver = prop["productionVersion"]
    latest_ver = prop["latestVersion"]

    target_version = prod_ver or latest_ver
    if not target_version:
        return prop_name, []

    try:
        assigned_hostnames = get_property_hostnames(
            session, base_url, prop_id, target_version, clean_contract_id, group_id
        )
        default_incoming_host = select_best_default_incoming_hostname(assigned_hostnames, prop_name)

        rule_tree = get_rule_tree(session, base_url, prop_id, target_version, clean_contract_id, group_id)
        origin_configs = extract_origin_behaviors(rule_tree, default_incoming_host=default_incoming_host)
    except Exception:
        return prop_name, []

    tested_pairs = set()
    found_expiring = []

    for item in origin_configs:
        origin_host = item["hostname"]
        sni = item["resolved_sni"]

        if not origin_host or item["origin_type"] == "NET_STORAGE":
            continue

        pair_key = (origin_host, sni)
        if pair_key in tested_pairs:
            continue
        tested_pairs.add(pair_key)

        cert_info = inspect_origin_leaf_cert(origin_host, sni)

        if "days_remaining" in cert_info and cert_info["days_remaining"] <= days_threshold:
            found_expiring.append({
                "contract_id": clean_contract_id,
                "property_name": prop_name,
                "property_id": prop_id,
                "property_version": target_version,
                "is_production": target_version == prod_ver,
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
            })

    return prop_name, found_expiring

def main():
    parser = argparse.ArgumentParser(
        description="Audit all origin certificates across an Akamai Contract expiring within 30 days and save to JSON."
    )
    parser.add_argument(
        "-c", "--contract",
        required=True,
        help="Contract ID (e.g., ctr_1-4GF84Q or 1-4GF84Q)"
    )
    parser.add_argument(
        "-s", "--section",
        required=True,
        help="Section name in .edgerc (e.g., akamaib)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Custom output JSON file path (default: expiring_origin_certs_<contract_id>.json)"
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
        default=8,
        help="Number of concurrent worker threads (default: 8)"
    )
    parser.add_argument(
        "--edgerc",
        default="~/.edgerc",
        help="Path to .edgerc config file (default: ~/.edgerc)"
    )
    args = parser.parse_args()

    clean_contract_id = args.contract if args.contract.startswith("ctr_") else f"ctr_{args.contract}"
    output_file = args.output or f"expiring_origin_certs_{clean_contract_id}.json"

    print(f"[*] Initializing session with .edgerc section: [{args.section}]")
    session, base_url = get_papi_session(section=args.section, edgerc_path=args.edgerc)

    print(f"[*] Scanning Contract: {clean_contract_id} (Threshold: <= {args.days} days)")
    properties = get_properties_for_contract(session, base_url, clean_contract_id)

    if not properties:
        print(f"[!] No properties found under contract {clean_contract_id}.")
        sys.exit(0)

    total_props = len(properties)
    print(f"[*] Found {total_props} total properties under contract {clean_contract_id}.")
    print(f"[*] Auditing with {args.threads} parallel threads (saving to {output_file})...\n")

    expiring_records = []
    completed_count = 0
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(audit_single_property, prop, session, base_url, clean_contract_id, args.days)
            for prop in properties
        ]

        for future in as_completed(futures):
            prop_name, results = future.result()
            with lock:
                completed_count += 1
                if results:
                    expiring_records.extend(results)
                
                # Format fixed-width progress message to prevent trailing character artifacts
                line = f"[{completed_count}/{total_props}] Scanned: {prop_name[:38]:<38} | Expiring Found: {len(expiring_records)}"
                # Pad to 90 chars and reset cursor to overwrite cleanly
                sys.stdout.write(f"\r{line:<90}")
                sys.stdout.flush()

    sys.stdout.write("\r" + " " * 92 + "\r")
    sys.stdout.flush()

    payload = {
        "metadata": {
            "contract_id": clean_contract_id,
            "section": args.section,
            "threshold_days": args.days,
            "total_properties_audited": total_props,
            "total_expiring_origins": len(expiring_records),
            "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        },
        "expiring_certificates": expiring_records
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print("=" * 85)
    print(f"[*] Audit Complete!")
    print(f"[*] Properties Audited     : {total_props}")
    print(f"[*] Expiring Certificates  : {len(expiring_records)}")
    print(f"[*] Results Saved To File  : {os.path.abspath(output_file)}")
    print("=" * 85)

if __name__ == "__main__":
    main()