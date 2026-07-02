#!/usr/bin/env python3
"""
Consolidate results from the OpenSCAP RHEL 9 STIG scan + the DISA API SRG and
ASD STIG DAST scanners into ONE multi-STIG checklist, emitted as both:
  * .ckl  (STIG Viewer 2 XML, multi-<iSTIG>)          -- widest compatibility
  * .cklb (STIG Viewer 3 JSON, multi-entry "stigs[]") -- STIG Viewer 3 / STIG Manager

"Evaluated controls only": each STIG contains just the controls the scanners
actually checked, with statuses + finding details. STIG Manager backfills the
remainder of each STIG (as Not_Reviewed) from its own loaded copy on import.

Usage:
  build-checklist.py --asset NAME [--target URL]
      [--api-json api.json] [--asd-json asd.json]
      [--oscap-xccdf results-xccdf.xml] [--oscap-datastream ssg-rhel9-ds.xml]
      --out-ckl out.ckl --out-cklb out.cklb
Any source may be omitted (e.g. the distroless micro app has no OpenSCAP scan).
"""
import argparse, json, re, sys, uuid, html
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

# ---- STIG identity metadata (STIG_INFO / stigs[] header) ---------------------
STIG_META = {
    "api": {"stigid": "API_Security_Requirements_Guide",
            "title": "DISA Application Programming Interface (API) Security Requirements Guide",
            "version": "1", "release": "Release: 0.1 (V1R0.1)",
            "display": "API SRG V1R0.1"},
    "asd": {"stigid": "Application_Security_and_Development_STIG",
            "title": "Application Security and Development Security Technical Implementation Guide",
            "version": "6", "release": "Release: 4 (V6R4)",
            "display": "ASD STIG V6R4"},
    "rhel9": {"stigid": "RHEL_9_STIG",
              "title": "Red Hat Enterprise Linux 9 Security Technical Implementation Guide",
              "version": "1", "release": "Release: 1",
              "display": "RHEL 9 STIG"},
}

# scanner FindingStatus -> checklist status
SCANNER_RANK = {"fail": 3, "error": 2, "skip": 2, "manual": 2, "pass": 1, "not_applicable": 0}
# oscap result -> checklist status
OSCAP_STATUS = {
    "pass": "NotAFinding", "fixed": "NotAFinding",
    "fail": "Open",
    "notapplicable": "Not_Applicable",
    "notchecked": "Not_Reviewed", "notselected": "Not_Reviewed",
    "informational": "Not_Reviewed", "unknown": "Not_Reviewed", "error": "Not_Reviewed",
}
CKL_TO_CKLB = {"NotAFinding": "not_a_finding", "Open": "open",
               "Not_Applicable": "not_applicable", "Not_Reviewed": "not_reviewed"}


def sev_to_cat(sev):
    s = (sev or "").lower()
    if s in ("critical", "high"):
        return "high"
    if s in ("medium", "med"):
        return "medium"
    return "low"


def agg_status(statuses):
    """Aggregate scanner statuses for one control into a CKL status."""
    ranks = [SCANNER_RANK.get(s, 2) for s in statuses]
    top = max(ranks) if ranks else 2
    if top == 3:
        return "Open"
    if top == 2:
        return "Not_Reviewed"
    if top == 1:
        return "NotAFinding"
    return "Not_Applicable"


def parse_scanner_json(path, key):
    """Return an iSTIG dict from a stig-*-scanner --format json file."""
    data = json.load(open(path, encoding="utf-8"))
    findings = data.get("findings", [])
    by_ctrl = {}
    for f in findings:
        vid = f.get("stig_id", "").strip()
        if not vid:
            continue
        by_ctrl.setdefault(vid, []).append(f)
    rules = []
    for vid, fs in sorted(by_ctrl.items()):
        status = agg_status([f.get("status", "manual") for f in fs])
        sev = sev_to_cat(fs[0].get("severity"))
        title = fs[0].get("title", vid)
        details_lines = []
        for f in fs:
            ep = f.get("endpoint") or STIG_META[key].get("display")
            st = (f.get("status") or "").upper()
            msg = f.get("details") or f.get("evidence") or ""
            details_lines.append(f"[{st}] {ep}: {msg}".rstrip(": ").strip())
        rules.append({
            "vuln_num": vid,
            "rule_id": f"{vid}r1_rule",           # scanners expose V-IDs, not SV-IDs
            "rule_ver": vid,
            "rule_title": title,
            "severity": sev,
            "status": status,
            "finding_details": "\n".join(details_lines),
            "comments": fs[0].get("fix", ""),
            "check_content": fs[0].get("fix", ""),
            "fix_text": fs[0].get("fix", ""),
            "ccis": [],
        })
    return {"meta": STIG_META[key], "rules": rules}


def localname(tag):
    return tag.rsplit("}", 1)[-1]


def parse_datastream(path):
    """Best-effort {ssg_rule_id: {title, stig_id, cce, ccis, srg}} from ssg-rhel9-ds.xml."""
    meta = {}
    if not path:
        return meta
    try:
        for _, el in ET.iterparse(path, events=("end",)):
            if localname(el.tag) != "Rule":
                continue
            rid = el.get("id", "")
            if "content_rule_" not in rid:
                el.clear(); continue
            short = rid.split("content_rule_", 1)[1]
            title, blob, ccis = "", [], []
            for d in el.iter():
                ln = localname(d.tag)
                if ln == "title" and not title:
                    title = "".join(d.itertext()).strip()
                if ln == "ident":
                    sysid = (d.get("system") or "").lower()
                    if "cci" in sysid and d.text:
                        ccis.append(d.text.strip())
                if d.text:
                    blob.append(d.text)
            text = " ".join(blob)
            stig = re.search(r"RHEL-09-\d{6}", text)
            cce = re.search(r"CCE-\d+-\d", text)
            vid = re.search(r"\bV-\d{6}\b", text)
            svid = re.search(r"\bSV-\d{6}r\d+_rule\b", text)
            meta[short] = {
                "title": title,
                "stig_id": stig.group(0) if stig else short,
                "cce": cce.group(0) if cce else "",
                "vid": vid.group(0) if vid else "",
                "svid": svid.group(0) if svid else "",
                "ccis": sorted(set(ccis)),
            }
            el.clear()
    except Exception as e:
        sys.stderr.write(f"warning: datastream parse failed ({e})\n")
    return meta


def load_na_rules(path):
    """Short rule ids a human determined Not Applicable to a container (from
    oscap/not-applicable.rules). These override an OpenSCAP 'fail' to N/A."""
    na = set()
    if not path:
        return na
    try:
        for line in open(path, encoding="utf-8"):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            rid = s.split()[0]
            na.add(rid.split("content_rule_", 1)[1] if "content_rule_" in rid else rid)
    except Exception:
        pass
    return na


def parse_oscap(xccdf_path, datastream_path, na_rules=None):
    """Return an iSTIG dict from an OpenSCAP results-xccdf.xml (RHEL 9 STIG)."""
    dsmeta = parse_datastream(datastream_path)
    na_rules = na_rules or set()
    rules = []
    for _, el in ET.iterparse(xccdf_path, events=("end",)):
        if localname(el.tag) != "rule-result":
            continue
        idref = el.get("idref", "")
        short = idref.split("content_rule_", 1)[1] if "content_rule_" in idref else idref
        sev = el.get("severity", "medium")
        result, cce = "", ""
        for ch in el:
            ln = localname(ch.tag)
            if ln == "result":
                result = (ch.text or "").strip()
            elif ln == "ident" and "cce" in (ch.get("system", "")).lower():
                cce = (ch.text or "").strip()
        # only include selected/evaluated rules
        if result in ("", "notselected"):
            el.clear(); continue
        m = dsmeta.get(short, {})
        stig_id = m.get("stig_id", short)
        vid = m.get("vid") or stig_id
        svid = m.get("svid") or f"{stig_id}r1_rule"
        status = OSCAP_STATUS.get(result, "Not_Reviewed")
        na_note = ""
        if short in na_rules:
            status = "Not_Applicable"
            na_note = " | Not Applicable to a container base image (documented determination)."
        rules.append({
            "vuln_num": vid,
            "rule_id": svid,
            "rule_ver": stig_id,
            "rule_title": m.get("title") or short,
            "severity": sev_to_cat(sev),
            "status": status,
            "finding_details": f"OpenSCAP result: {result} (rule {short}"
                               + (f", {cce or m.get('cce','')}" if (cce or m.get('cce')) else "") + ")" + na_note,
            "comments": f"SSG rule {short}",
            "check_content": f"Evaluated by OpenSCAP/SCAP Security Guide (rule {short}).",
            "fix_text": "",
            "ccis": m.get("ccis", []),
        })
        el.clear()
    return {"meta": STIG_META["rhel9"], "rules": rules}


# ---- writers ----------------------------------------------------------------
def esc(s):
    return html.escape(s or "", quote=False)


def si(name, data):
    return f"<SI_DATA><SID_NAME>{name}</SID_NAME><SID_DATA>{esc(str(data))}</SID_DATA></SI_DATA>"


def stig_data(attr, val):
    return (f"<STIG_DATA><VULN_ATTRIBUTE>{attr}</VULN_ATTRIBUTE>"
            f"<ATTRIBUTE_DATA>{esc(str(val))}</ATTRIBUTE_DATA></STIG_DATA>")


def write_ckl(istigs, asset, target, out_path):
    parts = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<!--DISA STIG Viewer :: 3.x  (generated by build-checklist.py)-->',
             '<CHECKLIST>',
             '<ASSET>',
             '<ROLE>None</ROLE><ASSET_TYPE>Computing</ASSET_TYPE>',
             f'<HOST_NAME>{esc(asset)}</HOST_NAME>',
             '<HOST_IP/><HOST_MAC/>',
             f'<HOST_FQDN>{esc(target)}</HOST_FQDN>',
             '<TARGET_COMMENT/><TECH_AREA/><TARGET_KEY/>',
             '<WEB_OR_DATABASE>true</WEB_OR_DATABASE>',
             f'<WEB_DB_SITE>{esc(target)}</WEB_DB_SITE><WEB_DB_INSTANCE/>',
             '</ASSET>',
             '<STIGS>']
    for ist in istigs:
        m = ist["meta"]
        parts.append('<iSTIG>')
        parts.append('<STIG_INFO>')
        parts.append(si("version", m["version"]))
        parts.append(si("stigid", m["stigid"]))
        parts.append(si("title", m["title"]))
        parts.append(si("releaseinfo", m["release"]))
        parts.append(si("uuid", str(uuid.uuid4())))
        parts.append('</STIG_INFO>')
        for r in ist["rules"]:
            parts.append('<VULN>')
            parts.append(stig_data("Vuln_Num", r["vuln_num"]))
            parts.append(stig_data("Severity", r["severity"]))
            parts.append(stig_data("Group_Title", r["rule_title"]))
            parts.append(stig_data("Rule_ID", r["rule_id"]))
            parts.append(stig_data("Rule_Ver", r["rule_ver"]))
            parts.append(stig_data("Rule_Title", r["rule_title"]))
            parts.append(stig_data("Vuln_Discuss", r.get("check_content", "")))
            parts.append(stig_data("Check_Content", r.get("check_content", "")))
            parts.append(stig_data("Fix_Text", r.get("fix_text", "")))
            parts.append(stig_data("STIGRef", m["title"]))
            for cci in r.get("ccis", []):
                parts.append(stig_data("CCI_REF", cci))
            parts.append(f'<STATUS>{r["status"]}</STATUS>')
            parts.append(f'<FINDING_DETAILS>{esc(r["finding_details"])}</FINDING_DETAILS>')
            parts.append(f'<COMMENTS>{esc(r["comments"])}</COMMENTS>')
            parts.append('<SEVERITY_OVERRIDE/><SEVERITY_JUSTIFICATION/>')
            parts.append('</VULN>')
        parts.append('</iSTIG>')
    parts.append('</STIGS></CHECKLIST>')
    open(out_path, "w", encoding="utf-8").write("\n".join(parts))


def write_cklb(istigs, asset, target, out_path):
    stigs = []
    for ist in istigs:
        m = ist["meta"]
        rules = []
        for r in ist["rules"]:
            rules.append({
                "group_id": r["vuln_num"],
                "group_id_src": r["vuln_num"],
                "rule_id": r["rule_id"],
                "rule_id_src": r["rule_id"],
                "rule_version": r["rule_ver"],
                "rule_title": r["rule_title"],
                "group_title": r["rule_title"],
                "severity": r["severity"],
                "weight": "10.0",
                "check_content": r.get("check_content", ""),
                "fix_text": r.get("fix_text", ""),
                "status": CKL_TO_CKLB.get(r["status"], "not_reviewed"),
                "finding_details": r["finding_details"],
                "comments": r["comments"],
                "ccis": r.get("ccis", []),
                "overrides": {},
            })
        stigs.append({
            "stig_name": m["title"],
            "display_name": m["display"],
            "stig_id": m["stigid"],
            "release_info": m["release"],
            "version": m["version"],
            "uuid": str(uuid.uuid4()),
            "reference_identifier": m["stigid"],
            "size": len(rules),
            "rules": rules,
        })
    doc = {
        "title": f"{asset} — consolidated STIG checklist",
        "id": str(uuid.uuid4()),
        "active": False,
        "mode": 2,
        "has_path": False,
        "target_data": {
            "target_type": "Computing", "host_name": asset, "ip_address": "",
            "mac_address": "", "fqdn": target, "comments": "",
            "role": "None", "is_web_database": True, "technology_area": "",
            "web_db_site": target, "web_db_instance": "",
        },
        "stigs": stigs,
        "cklb_version": "1.0",
        "generated": datetime.now(timezone.utc).isoformat(),
    }
    json.dump(doc, open(out_path, "w", encoding="utf-8"), indent=2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--asset", required=True)
    ap.add_argument("--target", default="")
    ap.add_argument("--api-json", default="")
    ap.add_argument("--asd-json", default="")
    ap.add_argument("--oscap-xccdf", default="")
    ap.add_argument("--oscap-datastream", default="")
    ap.add_argument("--na-rules", default="", help="oscap/not-applicable.rules to mark those controls N/A")
    ap.add_argument("--out-ckl", required=True)
    ap.add_argument("--out-cklb", required=True)
    a = ap.parse_args()

    istigs = []
    if a.oscap_xccdf:
        ist = parse_oscap(a.oscap_xccdf, a.oscap_datastream, load_na_rules(a.na_rules))
        if ist["rules"]:
            istigs.append(ist)
    if a.api_json:
        istigs.append(parse_scanner_json(a.api_json, "api"))
    if a.asd_json:
        istigs.append(parse_scanner_json(a.asd_json, "asd"))
    if not istigs:
        sys.exit("no inputs provided")

    write_ckl(istigs, a.asset, a.target, a.out_ckl)
    write_cklb(istigs, a.asset, a.target, a.out_cklb)
    total = sum(len(i["rules"]) for i in istigs)
    summary = ", ".join(f'{i["meta"]["display"]}={len(i["rules"])}' for i in istigs)
    print(f"checklist: {len(istigs)} STIG(s), {total} controls [{summary}] -> {a.out_ckl}, {a.out_cklb}")


if __name__ == "__main__":
    main()
