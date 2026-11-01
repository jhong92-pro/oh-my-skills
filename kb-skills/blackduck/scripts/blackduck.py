#!/usr/bin/env python3
"""Black Duck SCA CLI for the blackduck skill.

Server URL and API token come from config.properties in the skill folder.
Project and version: --project/--version, else config.properties.

Read-only: the only POST exchanges the API token for a session bearer token.
Every other call is a GET, and this tool never runs a scan.
"""
import argparse
import collections
import concurrent.futures
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CONFIG = Path(__file__).resolve().parent.parent / "config.properties"
PAGE_SIZE = 500
ACCEPT_JSON = "application/json"
ACCEPT_USER = "application/vnd.blackducksoftware.user-4+json"
ACCEPT_PROJECT = "application/vnd.blackducksoftware.project-detail-5+json"
ACCEPT_BOM = "application/vnd.blackducksoftware.bill-of-materials-6+json"
ACCEPT_COMPONENT = "application/vnd.blackducksoftware.component-detail-5+json"
ACCEPT_VULNERABILITY = "application/vnd.blackducksoftware.vulnerability-4+json"
ACCEPT_TEXT = "text/plain"

RISK_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "OK", "UNKNOWN"]
RISK_CATEGORIES = ["VULNERABILITY", "LICENSE", "OPERATIONAL", "VERSION", "ACTIVITY"]
# Listed as closed rather than open so that a status this tool has not seen stays visible.
CLOSED_REMEDIATION = {
    "IGNORED", "PATCHED", "MITIGATED", "REMEDIATION_COMPLETE", "DUPLICATE", "NOT_AFFECTED",
}


def configure_output():
    """Keep printing when a name holds a character the console encoding lacks, as with cp949."""
    sys.stdout.reconfigure(errors="backslashreplace")


def die(message):
    sys.exit(f"error: {message}")


def read_properties(key):
    if not CONFIG.is_file():
        return None
    # Settings are ASCII, so comments in any encoding (Windows ANSI, BOM, CRLF) must not stop the tool.
    text = CONFIG.read_bytes().decode("utf-8-sig", errors="replace")
    match = re.search(rf"^{re.escape(key)}=(.+)$", text, re.M)
    return match.group(1).strip() if match else None


HOST = (read_properties("url") or "").rstrip("/")
_bearer = None


def open_url(request, label, missing_ok=False):
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return response.read()
    except urllib.error.HTTPError as e:
        if e.code == 404 and missing_ok:
            return b""
        body = e.read().decode(errors="replace")
        try:
            detail = json.loads(body).get("errorMessage") or body[:200]
        except ValueError:
            detail = body[:200]
        if e.code == 401:
            detail = f"token rejected (issue a new one and update token in {CONFIG})"
        if e.code == 406:
            detail += " (pass a different media type with --accept)"
        die(f"HTTP {e.code} on {label}: {detail}")
    except urllib.error.URLError as e:
        die(f"cannot reach {HOST}: {e.reason} (check url in {CONFIG} and the network)")


def open_json(request, label):
    return json.loads(open_url(request, label))


def bearer():
    global _bearer
    if _bearer is None:
        if not HOST:
            die(f"no server: set url=<value> in {CONFIG}")
        token = read_properties("token")
        if not token:
            die(f"no token: set token=<value> in {CONFIG}")
        request = urllib.request.Request(
            f"{HOST}/api/tokens/authenticate",
            method="POST",
            headers={"Authorization": f"token {token}", "Accept": ACCEPT_USER},
        )
        _bearer = open_json(request, "/api/tokens/authenticate")["bearerToken"]
    return _bearer


def api_path(target):
    """Normalize to a server-relative path; the bearer token must never leave HOST."""
    if re.match(r"^[a-z][a-z0-9+.-]*://", target, re.I):
        if not target.startswith(f"{HOST}/"):
            die(f"refusing to send credentials to another host: {target}")
        return target[len(HOST):]
    return "/api/" + target.lstrip("/").removeprefix("api/")


def get(target, accept=ACCEPT_JSON, **params):
    path = api_path(target)
    if params:
        separator = "&" if "?" in path else "?"
        path += separator + urllib.parse.urlencode(params)
    request = urllib.request.Request(
        HOST + path, headers={"Authorization": f"Bearer {bearer()}", "Accept": accept}
    )
    return open_json(request, path)


def get_text(target):
    """Return the plain text at target, or an empty string when the server has none."""
    path = api_path(target)
    request = urllib.request.Request(
        HOST + path, headers={"Authorization": f"Bearer {bearer()}", "Accept": ACCEPT_TEXT}
    )
    return open_url(request, path, missing_ok=True).decode("utf-8", "replace").strip()


def get_all(target, accept=ACCEPT_JSON, **params):
    items, offset = [], 0
    while True:
        data = get(target, accept, limit=PAGE_SIZE, offset=offset, **params)
        batch = data.get("items", [])
        items += batch
        offset += PAGE_SIZE
        if not batch or offset >= data.get("totalCount", 0):
            return items


def links_of(resource):
    links = {}
    for link in resource.get("_meta", {}).get("links", []):
        links.setdefault(link["rel"], link["href"])
    return links


def find_project(args):
    name = getattr(args, "project", None) or read_properties("project")
    projects = get_all("projects", ACCEPT_PROJECT)
    names = ", ".join(p["name"] for p in projects) or "(none)"
    if not name:
        if len(projects) == 1:
            return projects[0]
        die(f"no project: pass --project or set project= in {CONFIG}. Available: {names}")
    for project in projects:
        if project["name"] == name:
            return project
    die(f"project not found: {name}. Available: {names}")


def find_version(args):
    project = find_project(args)
    name = getattr(args, "version", None) or read_properties("version")
    versions = get_all(links_of(project)["versions"], ACCEPT_PROJECT)
    names = ", ".join(v["versionName"] for v in versions) or "(none)"
    if not name:
        if len(versions) == 1:
            return project, versions[0]
        die(f"no version for {project['name']}: pass --version or set version= in {CONFIG}. "
            f"Available: {names}")
    for version in versions:
        if version["versionName"] == name:
            return project, version
    die(f"version not found in {project['name']}: {name}. Available: {names}")


def csv_upper(value):
    return {part.strip().upper() for part in value.split(",")} if value else None


def highest_risk(profile):
    counts = {c["countType"].upper(): c["count"] for c in (profile or {}).get("counts", [])}
    return next((level for level in RISK_ORDER if counts.get(level)), "UNKNOWN")


def risk_rank(level):
    return RISK_ORDER.index(level) if level in RISK_ORDER else len(RISK_ORDER)


def counter_line(counter, order=()):
    keys = [k for k in order if k in counter] + sorted(k for k in counter if k not in order)
    return " ".join(f"{k}={counter[k]}" for k in keys) or "-"


def bom_url(version):
    return version["_meta"]["href"] + "/components"


def origin_ids(component):
    ids = [o.get("externalId") for o in component.get("origins", []) if o.get("externalId")]
    return ", ".join(ids) or "-"


def license_names(component):
    return ", ".join(l.get("licenseDisplay", "?") for l in component.get("licenses", [])) or "-"


def components_of(version):
    return get_all(links_of(version)["components"], ACCEPT_BOM)


def component_label(component):
    return f"{component['componentName']} {component.get('componentVersionName', '(no version)')}"


def component_line(component):
    return (
        f"{component.get('policyStatus', '-'):16} "
        f"sec={highest_risk(component.get('securityRiskProfile')):8} "
        f"lic={highest_risk(component.get('licenseRiskProfile')):8} "
        f"ver={highest_risk(component.get('versionRiskProfile')):8} "
        f"{component_label(component)}  [{origin_ids(component)}]  "
        f"match={','.join(component.get('matchTypes', [])) or '-'}  license={license_names(component)}"
    )


def security_sort_key(component):
    return (risk_rank(highest_risk(component.get("securityRiskProfile"))), component["componentName"].lower())


def matches_query(component, query):
    needle = query.lower()
    return needle in component_label(component).lower() or needle in origin_ids(component).lower()


def vulnerabilities_of(version):
    return get_all(links_of(version)["vulnerable-components"], ACCEPT_BOM)


def vulnerability_of(row):
    return row["vulnerabilityWithRemediation"]


def is_open(row):
    return vulnerability_of(row).get("remediationStatus") not in CLOSED_REMEDIATION


def vulnerability_sort_key(row):
    v = vulnerability_of(row)
    return (risk_rank(v.get("severity")), -(v.get("overallScore") or 0), v["vulnerabilityName"], row["componentName"])


def related_name(vulnerability):
    related = vulnerability.get("relatedVulnerability")
    return related.rsplit("/", 1)[-1] if related else None


def unique_count(rows):
    return len({vulnerability_of(r)["vulnerabilityName"] for r in rows})


def cmd_projects(args):
    projects = get_all("projects", ACCEPT_PROJECT)
    if args.q:
        projects = [p for p in projects if args.q.lower() in p["name"].lower()]
    print(f"{len(projects)} project(s)")
    for project in projects:
        versions = get_all(links_of(project)["versions"], ACCEPT_PROJECT)
        print(f"{project['name']}  versions={', '.join(v['versionName'] for v in versions) or '-'}")


def cmd_versions(args):
    project = find_project(args)
    versions = get_all(links_of(project)["versions"], ACCEPT_PROJECT)
    print(f"Project: {project['name']}, {len(versions)} version(s)")
    for version in versions:
        links = links_of(version)
        status = get(links["bom-status"])
        policy = get(links["policy-status"], ACCEPT_BOM)
        print(f"{version['versionName']}  phase={version.get('phase')}  policy={policy.get('overallStatus')}  "
              f"bom={status.get('status')}  last_scan={status.get('lastScanDate', 'never')}")


def cmd_status(args):
    project, version = find_version(args)
    links = links_of(version)
    status = get(links["bom-status"])
    policy = get(links["policy-status"], ACCEPT_BOM)
    risk = get(links["riskProfile"])
    print(f"Project: {project['name']} / {version['versionName']}  "
          f"phase={version.get('phase')} distribution={version.get('distribution')}")
    print(f"BOM: {status.get('status')}  last_scan={status.get('lastScanDate', 'never')}  "
          f"last_bom_update={status.get('lastBomUpdateDate', 'never')}")
    if status.get("status") != "UP_TO_DATE":
        print("  WARNING: the BOM is not up to date, so these results may change.")

    print(f"Policy: {policy.get('overallStatus')}")
    counts = {c["name"]: c["value"] for c in policy.get("componentVersionStatusCounts", [])}
    print(f"  Server summary (its unit differs from BOM rows, see `violations`): {counter_line(counts)}")
    for rule in get_all(links["active-policy-rules"]):
        print(f"  Rule: {rule['name']}  category={rule.get('category')} severity={rule.get('severity')} "
              f"server_violation_count={rule.get('bomViolationCount')}")

    print("Risk (components by their highest risk):")
    print(f"  {'':14}" + "".join(f"{level:>9}" for level in RISK_ORDER))
    categories = risk.get("categories", {})
    for category in RISK_CATEGORIES:
        values = categories.get(category, {})
        print(f"  {category:14}" + "".join(f"{values.get(level, 0):>9}" for level in RISK_ORDER))

    rows = vulnerabilities_of(version)
    open_rows = [r for r in rows if is_open(r)]
    severities = collections.Counter(vulnerability_of(r).get("severity") for r in open_rows)
    print(f"Open vulnerabilities: {len(open_rows)} finding(s), {unique_count(open_rows)} unique  "
          f"{counter_line(severities, RISK_ORDER)}")
    print(f"Closed by remediation status: {len(rows) - len(open_rows)} finding(s)")

    print("Code locations:")
    for location in get_all(links["codelocations"]):
        print(f"  {location['name']}  updated={location.get('updatedAt')}")
    print(f"BOM page: {bom_url(version)}")


def cmd_vulns(args):
    project, version = find_version(args)
    rows = vulnerabilities_of(version)
    severities = csv_upper(args.severities)
    statuses = csv_upper(args.statuses)
    if severities:
        rows = [r for r in rows if vulnerability_of(r).get("severity") in severities]
    if args.component:
        needle = args.component.lower()
        rows = [r for r in rows
                if needle in f"{r['componentName']} {r.get('componentVersionName', '')} "
                             f"{r.get('componentVersionOriginId', '')}".lower()]
    status_counts = collections.Counter(vulnerability_of(r).get("remediationStatus") for r in rows)
    if statuses:
        rows = [r for r in rows if vulnerability_of(r).get("remediationStatus") in statuses]
    elif not args.all:
        rows = [r for r in rows if is_open(r)]
    rows.sort(key=vulnerability_sort_key)
    shown = rows[:args.limit]

    print(f"{project['name']} / {version['versionName']}: {len(rows)} finding(s), "
          f"{unique_count(rows)} unique, showing {len(shown)}")
    print(f"  severity: {counter_line(collections.Counter(vulnerability_of(r).get('severity') for r in rows), RISK_ORDER)}")
    print(f"  remediation (before the status filter): {counter_line(status_counts)}")
    for row in shown:
        v = vulnerability_of(row)
        related = related_name(v)
        print(f"{v.get('severity', '-'):8} {v.get('overallScore', '-'):>4} {v['vulnerabilityName']:18} "
              f"{v.get('remediationStatus', '-'):10} {row['componentName']} {row.get('componentVersionName', '')}  "
              f"[{row.get('componentVersionOriginId', '-')}]  {v.get('cweId', '-')}"
              + (f"  related={related}" if related else ""))


def cmd_vuln(args):
    detail = get(f"vulnerabilities/{urllib.parse.quote(args.id)}", ACCEPT_VULNERABILITY)
    print(f"{detail.get('name', args.id)}  severity={detail.get('severity')} source={detail.get('source')}  "
          f"published={detail.get('publishedDate')}")
    for key in ("overallScore", "exploitPublishDate", "vendorFixDate", "disclosureDate", "zeroDay", "underReview",
                "bdsaTags", "classifications", "cvss3", "cvss4"):
        if detail.get(key) not in (None, [], False):
            print(f"{key}: {json.dumps(detail[key], ensure_ascii=False)}")
    for key in ("title", "description", "technicalDescription", "workaround", "solution"):
        if detail.get(key):
            print(f"{key}: {detail[key]}")
    links = detail.get("_meta", {}).get("links", [])
    hrefs = lambda *rels: [link["href"] for link in links if link["rel"] in rels and link.get("href")]
    related = {href.rsplit("/", 1)[-1] for href in hrefs(
        "related-vulnerability", "related-vulnerabilities", "related-bdsa-vulnerability", "related-nvd-vulnerability")}
    if related:
        print(f"related: {', '.join(sorted(related))}")
    cwes = [href.rsplit("/", 1)[-1] for href in hrefs("cwes")]
    if cwes:
        print(f"cwe: {', '.join(cwes)}")
    for href in hrefs("reference")[:args.references]:
        print(f"reference: {href}")

    if getattr(args, "project", None) or read_properties("project"):
        project, version = find_version(args)
        # The server may record the same flaw under the CVE or the BDSA id, so match both.
        names = {args.id} | related
        rows = [r for r in vulnerabilities_of(version)
                if vulnerability_of(r)["vulnerabilityName"] in names or related_name(vulnerability_of(r)) in names]
        print(f"Affected in {project['name']} / {version['versionName']} (this id and related ids): "
              f"{len(rows)} finding(s)")
        for row in rows:
            v = vulnerability_of(row)
            print(f"  {v['vulnerabilityName']:18} {v.get('remediationStatus', '-'):10} {row['componentName']} "
                  f"{row.get('componentVersionName', '')}  [{row.get('componentVersionOriginId', '-')}]")
    else:
        print("Affected components: not checked, pass --project and --version")


def cmd_components(args):
    project, version = find_version(args)
    components = components_of(version)
    security = csv_upper(args.security)
    license_risk = csv_upper(args.license_risk)
    policy = csv_upper(args.policy)
    if args.q:
        components = [c for c in components if matches_query(c, args.q)]
    if security:
        components = [c for c in components if highest_risk(c.get("securityRiskProfile")) in security]
    if license_risk:
        components = [c for c in components if highest_risk(c.get("licenseRiskProfile")) in license_risk]
    if policy:
        components = [c for c in components if c.get("policyStatus") in policy]
    components.sort(key=security_sort_key)
    shown = components[:args.limit]
    print(f"{project['name']} / {version['versionName']}: {len(components)} component(s), showing {len(shown)}")
    print(f"  policy: {counter_line(collections.Counter(c.get('policyStatus') for c in components))}")
    print("  highest security risk: "
          + counter_line(collections.Counter(highest_risk(c.get('securityRiskProfile')) for c in components), RISK_ORDER))
    for component in shown:
        print(component_line(component))


def cmd_policies(args):
    project, version = find_version(args)
    rules = get_all(links_of(version)["active-policy-rules"])
    print(f"{project['name']} / {version['versionName']}: {len(rules)} rule(s) with violations")
    for rule in rules:
        print(f"{rule['name']}  category={rule.get('category')} severity={rule.get('severity')} "
              f"server_violation_count={rule.get('bomViolationCount')}")
        if rule.get("description"):
            print(f"  {rule['description']}")


def rules_for(component):
    href = links_of(component).get("policy-rules")
    return get_all(href, ACCEPT_BOM) if href else []


def cmd_violations(args):
    project, version = find_version(args)
    components = [c for c in components_of(version) if c.get("policyStatus") == "IN_VIOLATION"]
    components.sort(key=security_sort_key)
    bearer()  # authenticate once before the worker threads start
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        pairs = list(zip(components, pool.map(rules_for, components)))
    if args.rule:
        needle = args.rule.lower()
        pairs = [(c, rules) for c, rules in pairs if any(needle in r["name"].lower() for r in rules)]
    shown = pairs[:args.limit]
    print(f"{project['name']} / {version['versionName']}: {len(pairs)} component(s) in violation, "
          f"showing {len(shown)}")
    by_rule = collections.Counter(r["name"] for _, rules in pairs for r in rules)
    for name, count in by_rule.most_common():
        print(f"  {count:>4}  {name}")
    for component, rules in shown:
        print(component_line(component))
        for rule in rules:
            print(f"    rule: {rule['name']} (severity={rule.get('severity')})")


def format_guidance(term):
    if not term:
        return "none"
    risk = term.get("vulnerabilityRisk", {})
    counts = " ".join(f"{level[0].upper()}={risk.get(level, 0)}" for level in ("critical", "high", "medium", "low"))
    return f"{term.get('versionName')}  remaining: {counts}"


def print_guidance(label, guidance):
    print(f"  {label}: short={format_guidance(guidance.get('shortTerm'))}")
    print(f"  {label}: long={format_guidance(guidance.get('longTerm'))}")


def cmd_upgrade(args):
    project, version = find_version(args)
    components = [c for c in components_of(version) if matches_query(c, args.query)]
    components.sort(key=security_sort_key)
    shown = components[:args.limit]
    print(f"{project['name']} / {version['versionName']}: {len(components)} matching component(s), "
          f"showing {len(shown)}")
    for component in shown:
        print(component_line(component))
        for origin in component.get("origins", []):
            links = links_of(origin)
            print(f" origin: {origin.get('externalId', origin.get('name', '-'))}")
            if "upgrade-guidance" not in links:
                print("  no upgrade guidance")
                continue
            direct = get(links["upgrade-guidance"], ACCEPT_COMPONENT)
            print_guidance("guidance", direct)
            if "transitive-upgrade-guidance" in links:
                transitive = get(links["transitive-upgrade-guidance"], ACCEPT_COMPONENT)
                print_guidance("transitive", transitive)
            if "matched-files" in links:
                files = get(links["matched-files"], ACCEPT_BOM, limit=args.files)
                print(f"  matched files listed: {files.get('totalCount', 0)}")
                for item in files.get("items", []):
                    uri = item.get("filePath", {}).get("path") or item.get("uri", "?")
                    print(f"    {uri}")


def cmd_api(args):
    params = dict(pair.split("=", 1) for pair in args.params)
    print(json.dumps(get(args.path, args.accept, **params), indent=2, ensure_ascii=False))


def main():
    configure_output()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def command(name, func, help_text, target=True, project_only=False):
        p = sub.add_parser(name, help=help_text)
        p.set_defaults(func=func)
        if target or project_only:
            p.add_argument("--project")
        if target:
            p.add_argument("--version")
        return p

    p = command("projects", cmd_projects, "list projects and their versions", target=False)
    p.add_argument("-q", help="name substring")

    command("versions", cmd_versions, "policy and scan state of each version", target=False, project_only=True)
    command("status", cmd_status, "policy, risk, vulnerabilities, scan state of a version")

    p = command("vulns", cmd_vulns, "vulnerabilities, worst first; open ones by default")
    p.add_argument("--severities", help="CRITICAL,HIGH,MEDIUM,LOW")
    p.add_argument("--statuses", help="remediation statuses such as NEW,IGNORED")
    p.add_argument("--component", help="substring of the component name, version, or origin id")
    p.add_argument("--all", action="store_true", help="include closed remediation statuses")
    p.add_argument("--limit", type=int, default=50)

    p = command("vuln", cmd_vuln, "explain one vulnerability such as CVE-2021-21344 or BDSA-2026-6884")
    p.add_argument("id")
    p.add_argument("--references", type=int, default=5, help="reference links to list")

    p = command("components", cmd_components, "BOM components, highest security risk first")
    p.add_argument("-q", help="substring of the component name, version, or origin id")
    p.add_argument("--security", help="highest security risk: CRITICAL,HIGH,MEDIUM,LOW,OK")
    p.add_argument("--license-risk", help="highest license risk: CRITICAL,HIGH,MEDIUM,LOW,OK")
    p.add_argument("--policy", help="IN_VIOLATION,NOT_IN_VIOLATION,IN_VIOLATION_OVERRIDDEN")
    p.add_argument("--limit", type=int, default=50)

    command("policies", cmd_policies, "policy rules that have violations in this version")

    p = command("violations", cmd_violations, "components in policy violation and the rules they break")
    p.add_argument("--rule", help="rule name substring")
    p.add_argument("--limit", type=int, default=50)

    p = command("upgrade", cmd_upgrade, "upgrade guidance and matched files for matching components")
    p.add_argument("query", help="substring of the component name, version, or origin id")
    p.add_argument("--files", type=int, default=5, help="matched files to list per origin")
    p.add_argument("--limit", type=int, default=10)

    p = command("api", cmd_api, "raw GET: api projects limit=10", target=False)
    p.add_argument("path", help="path under /api, or a full URL on the configured server")
    p.add_argument("params", nargs="*", metavar="key=value")
    p.add_argument("--accept", default=ACCEPT_JSON, help="media type, when the server answers HTTP 406")

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
