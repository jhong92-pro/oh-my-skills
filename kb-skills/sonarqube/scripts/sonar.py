#!/usr/bin/env python3
"""SonarQube 8.9 CLI for the sonarqube skill.

Server URL and token come from config.properties in the skill folder.
Project: --project, else config.properties, sonar-project.properties.

Read-only: every API call is a GET, and this tool never runs an analysis.
"""
import argparse
import base64
import html
import json
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CONFIG = Path(__file__).resolve().parent.parent / "config.properties"
PAGE_MAX = 500  # server-side maximum for ps
HOTSPOT_FETCH_MAX = 10000
RATINGS = {"1.0": "A", "2.0": "B", "3.0": "C", "4.0": "D", "5.0": "E"}
OVERVIEW_METRICS = [
    "bugs", "reliability_rating", "vulnerabilities", "security_rating",
    "security_hotspots", "security_review_rating", "code_smells", "sqale_rating",
    "sqale_index", "coverage", "duplicated_lines_density", "ncloc",
]


def die(message):
    sys.exit(f"error: {message}")


def repo_root():
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True
    )
    return Path(result.stdout.strip()) if result.returncode == 0 else Path.cwd()


def read_properties(path, key):
    if not path.is_file():
        return None
    match = re.search(rf"^{re.escape(key)}=(.+)$", path.read_text(), re.M)
    return match.group(1).strip() if match else None


HOST = (read_properties(CONFIG, "url") or "http://localhost:9000").rstrip("/")


def token():
    value = read_properties(CONFIG, "token")
    if not value:
        die(f"no token: set token=<value> in {CONFIG}")
    return value


def project_key(args):
    root = repo_root()
    key = (
        getattr(args, "project", None)
        or read_properties(CONFIG, "project")
        or read_properties(root / "sonar-project.properties", "sonar.projectKey")
    )
    if not key:
        die("no project key: pass --project (the `projects` command lists them)")
    return key


def get(path, **params):
    params = {k: v for k, v in params.items() if v is not None}
    url = f"{HOST}/api/{path.lstrip('/').removeprefix('api/')}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    credentials = base64.b64encode(f"{token()}:".encode()).decode()
    request = urllib.request.Request(url, headers={"Authorization": f"Basic {credentials}"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        try:
            detail = "; ".join(m["msg"] for m in json.loads(body)["errors"])
        except (ValueError, KeyError, TypeError):
            detail = body[:200]
        if e.code == 401:
            detail = "token rejected"
        die(f"HTTP {e.code} on {path}: {detail}")
    except urllib.error.URLError as e:
        die(f"cannot reach {HOST}: {e.reason} (check url in {CONFIG} and the network)")


def paged(path, item_key, limit, **params):
    """Return (items, total), fetching pages until `limit` items are collected."""
    items, page = [], 1
    while True:
        data = get(path, p=page, ps=min(PAGE_MAX, limit), **params)
        batch = data[item_key]
        items += batch
        total = data["paging"]["total"]
        if not batch or len(items) >= min(limit, total):
            return items[:limit], total
        page += 1


def file_of(component, project):
    return component.removeprefix(f"{project}:")


def measures(project):
    data = get("measures/component", component=project, metricKeys=",".join(OVERVIEW_METRICS))
    return {m["metric"]: m.get("value") for m in data["component"]["measures"]}


def format_metric(metric, value):
    if value is None:
        return "n/a"
    if metric.endswith("_rating"):
        return RATINGS.get(value, value)
    if metric == "sqale_index":
        return f"{int(value) / 60:.1f}h"
    if metric in ("coverage", "duplicated_lines_density"):
        return f"{value}%"
    return value


def print_overview(project):
    gate = get("qualitygates/project_status", projectKey=project)["projectStatus"]
    conditions = gate.get("conditions", [])
    print(f"Quality gate: {gate['status']} ({len(conditions)} conditions evaluated)")
    if not conditions:
        print("  WARNING: no conditions were evaluated, so this status says nothing about quality.")
        print("  The gate only checks new code and this project has no new-code baseline yet.")
    else:
        print("  Note: the gate only checks new code, so this status does not cover existing code.")
    for c in conditions:
        threshold = c.get("errorThreshold", "-")
        print(f"  {c['status']:5} {c['metricKey']} = {c.get('actualValue', 'n/a')} "
              f"({c['comparator']} {threshold} fails)")

    values = measures(project)
    print("Overall code:")
    print(f"  Reliability      {format_metric('reliability_rating', values.get('reliability_rating'))}"
          f"  bugs={values.get('bugs')}")
    print(f"  Security         {format_metric('security_rating', values.get('security_rating'))}"
          f"  vulnerabilities={values.get('vulnerabilities')}")
    print(f"  Security review  {format_metric('security_review_rating', values.get('security_review_rating'))}"
          f"  hotspots={values.get('security_hotspots')}")
    print(f"  Maintainability  {format_metric('sqale_rating', values.get('sqale_rating'))}"
          f"  code_smells={values.get('code_smells')}"
          f" debt={format_metric('sqale_index', values.get('sqale_index'))}")
    print(f"  Coverage={format_metric('coverage', values.get('coverage'))}"
          f"  Duplication={format_metric('duplicated_lines_density', values.get('duplicated_lines_density'))}"
          f"  Lines={values.get('ncloc')}")

    current = get("ce/component", component=project).get("current")
    if current:
        print(f"Last analysis: {current.get('executedAt')} status={current['status']}")
        task = get("ce/task", id=current["id"], additionalFields="warnings")["task"]
        for warning in task.get("warnings", []):
            print(f"  Analysis warning: {warning}")
    print(f"Dashboard: {HOST}/dashboard?id={urllib.parse.quote(project)}")


def cmd_projects(args):
    items, total = paged("projects/search", "components", args.limit, q=args.q)
    print(f"{total} project(s)")
    for p in items:
        print(f"{p['key']}  last_analysis={p.get('lastAnalysisDate', 'never')}  "
              f"revision={p.get('revision', '-')[:8]}  {p['visibility']}")


def cmd_status(args):
    print(f"Project: {project_key(args)}")
    print_overview(project_key(args))


def cmd_issues(args):
    project = project_key(args)
    component = f"{project}:{args.path}" if args.path else project
    filters = dict(
        componentKeys=component,
        resolved=None if args.statuses else "false",
        statuses=args.statuses,
        severities=args.severities,
        types=args.types,
        rules=args.rules,
        sinceLeakPeriod="true" if args.new else None,
    )
    items, total = paged("issues/search", "issues", args.limit, s="SEVERITY", asc="false", **filters)
    # A facet ignores the filter on its own property, so its counts would not match the results.
    wanted = [f for f, value in (("severities", args.severities), ("types", args.types)) if not value]
    facets = get("issues/search", ps=1, facets=",".join(wanted), **filters)["facets"] if wanted else []
    print(f"{total} issue(s), showing {len(items)}")
    for facet in facets:
        counts = " ".join(f"{v['val']}={v['count']}" for v in facet["values"] if v["count"])
        print(f"  {facet['property']}: {counts or '-'}")
    for i in items:
        location = file_of(i["component"], project)
        if i.get("line"):
            location += f":{i['line']}"
        print(f"{i['severity']:8} {i['type']:16} {location}  {i['rule']}  {i['message']}  [{i['key']}]")


def cmd_hotspots(args):
    project = project_key(args)
    # hotspots/search is internal, but it is the only way to list hotspots. The server can't
    # sort by probability, so fetch everything before applying the limit.
    items, total = paged(
        "hotspots/search", "hotspots", HOTSPOT_FETCH_MAX,
        projectKey=project, status=args.status,
        sinceLeakPeriod="true" if args.new else None,
    )
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    items.sort(key=lambda h: order.get(h["vulnerabilityProbability"], 3))
    items = items[:args.limit]
    print(f"{total} hotspot(s) with status={args.status}, showing {len(items)}")
    for h in items:
        location = file_of(h["component"], project)
        if h.get("line"):
            location += f":{h['line']}"
        print(f"{h['vulnerabilityProbability']:6} {h['securityCategory']:24} {location}  {h['message']}  [{h['key']}]")


def cmd_files(args):
    project = project_key(args)
    data = get(
        "measures/component_tree", component=project, qualifiers="FIL", strategy="all",
        metricKeys=args.metric, s="metric", metricSort=args.metric, asc="false",
        metricSortFilter="withMeasuresOnly", ps=min(args.limit, PAGE_MAX),
    )
    print(f"Top files by {args.metric}")
    for c in data["components"]:
        value = next((m.get("value") for m in c.get("measures", []) if m["metric"] == args.metric), "0")
        print(f"{value:>8}  {c.get('path', c['key'])}")


def cmd_rule(args):
    rule = get("rules/show", key=args.key)["rule"]
    print(f"{rule['key']}: {rule['name']} ({rule['severity']}, {rule['type']})")
    text = re.sub(r"<[^>]+>", " ", rule.get("htmlDesc", ""))
    print(re.sub(r"[ \t]+", " ", html.unescape(text)).strip())


def cmd_history(args):
    project = project_key(args)
    data = get(
        "measures/search_history", component=project, metrics=args.metrics, ps=PAGE_MAX
    )
    for measure in data["measures"]:
        print(measure["metric"])
        for point in measure["history"][-args.limit:]:
            print(f"  {point['date']}  {point.get('value', 'n/a')}")


def cmd_catalog(args):
    data = get("webservices/list", include_internals="true")
    needle = (args.filter or "").removeprefix("api/")
    for service in data["webServices"]:
        for action in service["actions"]:
            name = f"{service['path'].removeprefix('api/')}/{action['key']}"
            if needle not in name:
                continue
            flags = ("POST" if action.get("post") else "GET") + (" internal" if action.get("internal") else "")
            params = action.get("params", [])
            required = lambda p: "*" if p.get("required") else ""
            if args.filter and args.verbose:
                print(f"{name} [{flags}]\n  {action.get('description', '')[:400]}")
                for p in params:
                    print(f"  {p['key']}{required(p)}: {p.get('description', '')[:160]}")
            else:
                print(f"{name} [{flags}] {' '.join(p['key'] + required(p) for p in params)}")


def cmd_api(args):
    params = dict(pair.split("=", 1) for pair in args.params)
    print(json.dumps(get(args.path, **params), indent=2, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def command(name, func, help_text, project=True):
        p = sub.add_parser(name, help=help_text)
        p.set_defaults(func=func)
        if project:
            p.add_argument("--project")
        return p

    p = command("projects", cmd_projects, "list projects", project=False)
    p.add_argument("-q")
    p.add_argument("--limit", type=int, default=100)

    command("status", cmd_status, "quality gate, ratings, measures, last analysis")

    p = command("issues", cmd_issues, "search issues, most severe first; open ones by default")
    p.add_argument("--severities", help="BLOCKER,CRITICAL,MAJOR,MINOR,INFO")
    p.add_argument("--types", help="BUG,VULNERABILITY,CODE_SMELL")
    p.add_argument("--statuses", help="OPEN,CONFIRMED,REOPENED,RESOLVED,CLOSED")
    p.add_argument("--rules", help="for example python:S3516")
    p.add_argument("--path", help="file or directory relative to the repo root")
    p.add_argument("--new", action="store_true", help="only issues in the new-code period")
    p.add_argument("--limit", type=int, default=50)

    p = command("hotspots", cmd_hotspots, "search security hotspots, highest probability first")
    p.add_argument("--status", default="TO_REVIEW", help="TO_REVIEW or REVIEWED")
    p.add_argument("--new", action="store_true")
    p.add_argument("--limit", type=int, default=50)

    p = command("files", cmd_files, "files ranked by a metric")
    p.add_argument("--metric", default="code_smells")
    p.add_argument("--limit", type=int, default=10)

    p = command("rule", cmd_rule, "explain a rule", project=False)
    p.add_argument("key")

    p = command("history", cmd_history, "metric values across analyses")
    p.add_argument("--metrics", default="bugs,vulnerabilities,code_smells")
    p.add_argument("--limit", type=int, default=10)

    p = command("catalog", cmd_catalog, "list web service actions and parameters", project=False)
    p.add_argument("filter", nargs="?", help="substring such as issues/search")
    p.add_argument("-v", "--verbose", action="store_true", help="include descriptions")

    p = command("api", cmd_api, "raw GET: api issues/tags ps=10", project=False)
    p.add_argument("path")
    p.add_argument("params", nargs="*", metavar="key=value")

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
