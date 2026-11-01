#!/usr/bin/env python3
"""Write the KB Kookmin Bank open source notice as HTML for the blackduck-notice skill.

Fills templates/notice-template.html with BOM data from Black Duck. Server access and
config.properties are shared with the blackduck skill, whose client this script imports.

Writes one local HTML file and changes nothing on the server.
"""
import argparse
import collections
import concurrent.futures
import datetime
import html
import re
import sys
from pathlib import Path

SKILLS_DIR = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(SKILLS_DIR / "blackduck" / "scripts"))
from blackduck import bearer, components_of, configure_output, die, find_version, get, get_all, get_text, links_of  # noqa: E402

# Hangul, kana, CJK, and Cyrillic: the notice is English only.
NON_ENGLISH = re.compile(r"[\u0400-\u04ff\u3040-\u30ff\u3400-\u9fff\uac00-\ud7a3]")
# License families that can carry obligations beyond attribution, such as offering source code.
NOTICE_REVIEW_FAMILIES = {"RECIPROCAL", "RECIPROCAL_AGPL", "WEAK_RECIPROCAL", "UNKNOWN"}
# The notice wording and layout live only in this template.
NOTICE_TEMPLATE = Path(__file__).resolve().parent.parent / "templates" / "notice-template.html"
NOTICE_BLOCK = re.compile(r"<!-- BEGIN (\w+) -->(.*?)<!-- END \1 -->", re.S)


def license_leaves(entry):
    children = entry.get("licenses") or []
    return [leaf for child in children for leaf in license_leaves(child)] if children else [entry]


def notice_details(component):
    """Collect the server data one component needs: homepage and copyright statements."""
    copyrights = {}
    for origin in component.get("origins", []):
        href = links_of(origin).get("component-origin-copyrights")
        for item in get_all(href) if href else []:
            text = " ".join((item.get("updatedCopyright") or "").split())
            # Inactive statements are mostly scanner noise such as "(c) data" or "N/A".
            if item.get("active") and text:
                copyrights.setdefault(text.casefold(), text)
    return {"url": links_of(component).get("component-home"), "copyrights": copyrights}


def suspect_copyright(text):
    """Flag scanner output that looks like code or prose rather than a copyright statement."""
    return len(text) > 160 or bool(re.search(r"[;{}=]|\(\)| @ ", text))


def copyright_year(text):
    current = datetime.date.today().year
    years = [int(year) for year in re.findall(r"\b(19[7-9]\d|20\d\d)\b", text)]
    return max((year for year in years if year <= current), default=0)


def latest_copyright(statements):
    """Pick the statement with the latest year, preferring ones that do not look like noise."""
    rank = lambda text: (not suspect_copyright(text), copyright_year(text))
    ordered = sorted(statements, key=str.casefold)
    if not ordered:
        return None, 0
    best = max(ordered, key=rank)
    return best, sum(1 for text in ordered if rank(text) == rank(best)) - 1


def notice_label(entry):
    return f"{entry['name']} {entry['version']}".rstrip()


def read_notice_template():
    if not NOTICE_TEMPLATE.is_file():
        die(f"notice template not found: {NOTICE_TEMPLATE}")
    template = NOTICE_TEMPLATE.read_text(encoding="utf-8-sig")
    blocks = {match.group(1) for match in NOTICE_BLOCK.finditer(template)}
    if blocks != {"COMPONENT", "LICENSE"}:
        die(f"{NOTICE_TEMPLATE} must contain exactly the COMPONENT and LICENSE blocks, found: {sorted(blocks)}")
    return template


def fill_notice_block(block, values):
    """Fill one repeated block. A line holding only an empty value is removed with its line break."""
    def lookup(match):
        if match.group(1) not in values:
            die(f"unknown placeholder in {NOTICE_TEMPLATE}: {match.group(0)}")
        return values[match.group(1)] or ""

    def drop_empty_line(match):
        # The value may directly follow a closing tag, because a heading holds its own line break.
        return match.group(1) if not values.get(match.group(2)) and match.group(2) in values else match.group(0)

    block = re.sub(r"(^|>)\{\{(\w+)\}\}\n", drop_empty_line, block, flags=re.M)
    return re.sub(r"\{\{(\w+)\}\}", lambda match: html.escape(lookup(match), quote=False), block)


def notice_html(template, entries, sections):
    rows = {
        "COMPONENT": entries,
        "LICENSE": [{"name": s["name"], "components": ", ".join(s["labels"]), "text": s["text"]} for s in sections],
    }
    return NOTICE_BLOCK.sub(
        lambda match: "".join(fill_notice_block(match.group(2), row) for row in rows[match.group(1)]), template
    )


def print_review(label, names):
    print(f"  {label}: {len(names)}")
    if names:
        print(f"    {', '.join(sorted(names, key=str.casefold))}")


def cmd_notice(args):
    output = Path(args.output)
    if output.exists() and not args.force:
        die(f"{output} already exists: pass --force to overwrite it")
    template = read_notice_template()
    project, version = find_version(args)
    status = get(links_of(version)["bom-status"])
    all_components = components_of(version)
    components = [c for c in all_components if not c.get("ignored") and c.get("inAttributionReport", True)]
    bearer()  # authenticate once before the worker threads start
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        details = list(pool.map(notice_details, components))

    merged, by_license = {}, {}
    no_text, copyleft, unreviewed = set(), collections.defaultdict(set), set()
    for component, detail in zip(components, details):
        name, component_version = component["componentName"], component.get("componentVersionName", "")
        entry = merged.setdefault((name, component_version), {
            "name": name, "version": component_version, "url": None, "statements": {}, "licenses": [],
        })
        label = notice_label(entry)
        entry["url"] = entry["url"] or detail["url"]
        entry["statements"].update(detail["copyrights"])
        for license_entry in component.get("licenses", []):
            display = license_entry.get("licenseDisplay") or "Unknown License"
            if display not in entry["licenses"]:
                entry["licenses"].append(display)
            for leaf in license_leaves(license_entry):
                family = (leaf.get("licenseFamilyName") or "UNKNOWN").upper()
                if family in NOTICE_REVIEW_FAMILIES:
                    copyleft[leaf.get("licenseDisplay", "Unknown License")].add(label)
                # For an unidentified license the server returns a placeholder sentence, not a license.
                if family == "UNKNOWN" or not leaf.get("license"):
                    no_text.add(label)
                    continue
                license_id = leaf["license"].rsplit("/", 1)[-1]
                by_license.setdefault(license_id, {"name": leaf["licenseDisplay"], "labels": set()})["labels"].add(label)
        if not component.get("licenses"):
            no_text.add(label)
        if component.get("reviewStatus") != "REVIEWED":
            unreviewed.add(label)

    sort_key = lambda e: (e["name"].casefold(), e["version"])
    omitted, tied, entries = 0, 0, []
    for entry in sorted(merged.values(), key=sort_key):
        statements = list(entry["statements"].values())
        chosen, ties = latest_copyright(statements)
        omitted += max(len(statements) - 1, 0)
        tied += 1 if ties else 0
        entries.append({"label": notice_label(entry), "license": ", ".join(entry["licenses"]) or "Unknown License",
                        "copyright": chosen, "url": entry["url"]})
    order = {entry["label"]: index for index, entry in enumerate(entries)}
    sections = []
    for license_id, section in sorted(by_license.items(), key=lambda item: item[1]["name"].casefold()):
        text = get_text(f"licenses/{license_id}/text")
        labels = sorted(section["labels"], key=order.get)
        if text:
            sections.append({"name": section["name"], "labels": labels, "text": text})
        else:
            no_text.update(labels)

    # Fixed line endings, so the same data gives the same file on every operating system.
    with open(output, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(notice_html(template, entries, sections))

    print(f"Wrote {output} from {project['name']} / {version['versionName']}")
    print(f"  bom={status.get('status')} last_scan={status.get('lastScanDate', 'never')}")
    print(f"  {len(entries)} component version(s), {len(sections)} license text(s), "
          f"{len(all_components) - len(components)} BOM row(s) excluded as ignored or not in attribution")
    print("Review before release:")
    print_review("no confirmed copyright (line left out)", {e["label"] for e in entries if not e["copyright"]})
    print_review("no homepage (line left out)", {e["label"] for e in entries if not e["url"]})
    print_review("license unidentified or without text", no_text)
    print(f"  copyright statements omitted, only the latest is shown: {omitted}")
    print(f"  components with another statement from the same latest year: {tied}")
    print_review("shown copyright has no year",
                 {e["label"] for e in entries if e["copyright"] and not copyright_year(e["copyright"])})
    suspects = [f"{e['label']}: {e['copyright'][:100]}"
                for e in entries if e["copyright"] and suspect_copyright(e["copyright"])]
    print(f"  shown copyright looks like code or prose: {len(suspects)}")
    for line in suspects[:args.show]:
        print(f"    {line}")
    if len(suspects) > args.show:
        print(f"    ... {len(suspects) - args.show} more")
    print(f"  not marked reviewed on the server: {len(unreviewed)}")
    print_review("non-English characters in third party names or copyrights",
                 {e["label"] for e in entries if NON_ENGLISH.search(f"{e['label']} {e['copyright'] or ''}")})
    print_review("non-English characters in license texts",
                 {section["name"] for section in sections if NON_ENGLISH.search(section["text"])})
    print(f"  copyleft or unknown license families: {len(copyleft)}")
    for name, labels in sorted(copyleft.items()):
        print(f"    {name}: {', '.join(sorted(labels, key=str.casefold))}")


def main():
    configure_output()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--project")
    parser.add_argument("--version")
    parser.add_argument("--output", default="oss-notice.html")
    parser.add_argument("--force", action="store_true", help="overwrite an existing output file")
    parser.add_argument("--show", type=int, default=30, help="suspect copyright lines to list")
    cmd_notice(parser.parse_args())


if __name__ == "__main__":
    main()
