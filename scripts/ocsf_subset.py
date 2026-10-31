# Builds pkg/ocsf/schema.json: a pinned, trimmed copy of the official OCSF schema.
#
#   curl -o export.json "https://schema.ocsf.io/export/schema?profiles="
#   python -I scripts/ocsf_subset.py export.json pkg/ocsf/schema.json
#
# Keeps only the classes ConfigBridge stores, every object they reach, and the
# fields the validator needs (type, object_type, is_array, requirement, enum keys
# and captions). Descriptions are dropped. Review the diff when bumping versions.
import json
import sys

src, dst = sys.argv[1], sys.argv[2]
CLASSES = ["vulnerability_finding", "detection_finding", "user_inventory", "inventory_info", "authentication"]
KEEP = ("type", "object_type", "is_array", "requirement")

export = json.load(open(src, encoding="utf-8"))


def slim(attrs):
    out = {}
    for name, a in sorted(attrs.items()):
        s = {k: a[k] for k in KEEP if k in a}
        if "enum" in a:
            s["enum"] = {k: v.get("caption", k) for k, v in sorted(a["enum"].items())}
        out[name] = s
    return out


classes = {}
todo = []
for name in CLASSES:
    c = export["classes"][name]
    classes[name] = {"uid": c["uid"], "caption": c["caption"], "category_uid": c["category_uid"],
                     "category_name": c["category_name"], "attributes": slim(c["attributes"])}
    todo += [a.get("object_type") for a in c["attributes"].values()]

objects = {}
while todo:
    name = todo.pop()
    if not name or name in objects:
        continue
    o = export["objects"][name]
    objects[name] = {"attributes": slim(o["attributes"])}
    todo += [a.get("object_type") for a in o["attributes"].values()]

types = {k: (v.get("type") or k) for k, v in sorted(export["types"].items())}
out = {"version": export["version"], "types": types, "classes": classes, "objects": dict(sorted(objects.items()))}
json.dump(out, open(dst, "w", encoding="utf-8", newline="\n"), indent=1, sort_keys=True)
print(f"OCSF {out['version']}: {len(classes)} classes, {len(objects)} objects -> {dst}")
