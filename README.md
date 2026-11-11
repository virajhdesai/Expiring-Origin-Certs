Akamai Origin Certificate Expiry Auditor: An automated audit tool that inspects origin server behaviors across Akamai Property Manager (PAPI) configurations. It parses rule criteria and forwardHostHeader settings, maps the effective Server Name Indication (SNI), performs direct TLS handshakes against origin servers, and flags certificates expiring within a configurable threshold (default: 30 days) to prevent origin outage alerts.

Prerequisites & Dependencies Installed: The script requires Python 3.8+ and three core third-party libraries:\
pip install edgegrid-python\
pip install requests\
pip install cryptography

edgegrid-python : Akamai EdgeGrid authentication library; parses ~/.edgerc tokens and signs API requests.
requests: requests handles REST HTTP requests to the Akamai Property Manager API (PAPI).
cryptography : Parses raw DER-encoded X.509 certificates from TLS sockets to extract validity dates, subjects, and SHA-1 fingerprints.

Akamai Credentials Setup (.edgerc)The script expects API credentials stored in your ~/.edgerc file (typically C:\Users\<username>\.edgerc on Windows or ~/.edgerc on Linux/macOS) with Property Manager (PAPI) Read/Write permissions.The script automatically detects account switch keys under any of the following key names inside the target section:

[akamaib]\
client_secret = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\
host = akab-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx.luna.akamaiapis.net\
access_token = akab-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx\
client_token = akab-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx\
account_key = 15R-84AB:1-5G3LB

Akamai origin alerts provide configuration names, origin IPs, forward host headers, and SHA-1 fingerprints (LEAF CERT SHA1 HEX).The script maps these alerts back to Property Manager rules and verifies the certificate directly at the origin layer.

Accurate SNI / Forward Host Header Resolution:Origin servers frequently serve multiple certificates via virtual hosting. Passing the wrong SNI returns the default/fallback certificate rather than the one Akamai connects to.

Rule Criteria Tracking: Recursively inspects parent and child rule criteria (hostname is one of...) to identify the active hostname for that behavior branch.

Behavior Mapping: Evaluates options.forwardHostHeader:REQUEST_HOST_HEADER / INCOMING_HOST_HEADER: Uses the rule's matched hostname or prioritizes the primary production hostname over other hostnames.
ORIGIN_HOSTNAME: Uses origin.options.hostname.
CUSTOM: Uses origin.options.customForwardHostHeader.

Multi-Scope Auditing:
Single Property (check_origin_certs.py): Resolves property names or direct numeric property ID and inspects all origin endpoints in that configuration.
Contract-Wide (check_contract_origin_certs.py): Enumerates all groups under a contract, discovers all production properties, and audits every origin in parallel.

Performance & Scalability via Multithreading:Network I/O operations (DNS lookups, TCP handshakes, TLS handshakes) are bound by network latency, leaving the CPU idle.Leverages Python's concurrent.futures.
ThreadPoolExecutor to run origin and property audits concurrently (reducing runtimes for hundreeds of properties from hours to minutes).Implements thread-safe locking and fixed-width terminal output to avoid PowerShell carriage return (\r) visual bugs.

Non-Intrusive JSON Deliverable:Filters out healthy certificates and outputs only those expiring within the threshold (<= 30 days).Saves clean, parseable JSON files containing the property ID, version, rule location, origin hostname, effective SNI, certificate subject, expiration timestamp, days remaining, and SHA-1 hex fingerprints.

# Direct run using property name
python check_origin_certs.py -p shop.example.com -s akamaib

# Contract-Wide Audit
python check_contract_origin_certs.py -c ctr_X-XXXXXX -s akamaib