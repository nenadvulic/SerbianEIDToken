#!/usr/bin/env python3
"""Checks the String Catalogs of the token app and extension.

For every key: `sr` and `sr-Latn` must be translated (state "translated"),
the Serbian plural variants must cover one/few/other, and every `sr-Latn`
value must be the exact Gaj transliteration of the `sr` value.

With --build DIR (an xcodebuild -derivedDataPath built with
SWIFT_EMIT_LOC_STRINGS=YES), also checks that the keys the compiler extracted
from each target match the target's catalog exactly.

Usage: scripts/check-l10n.py [--build TokenApp/build]
"""
import argparse
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOGS = {
    "SerbianEIDTokenApp": os.path.join(ROOT, "TokenApp/App/Localizable.xcstrings"),
    "SerbianEIDToken": os.path.join(ROOT, "TokenApp/Extension/Localizable.xcstrings"),
}
SERBIAN_PLURALS = {"one", "few", "other"}
CYR = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "ђ": "đ", "е": "e", "ж": "ž",
    "з": "z", "и": "i", "ј": "j", "к": "k", "л": "l", "љ": "lj", "м": "m", "н": "n",
    "њ": "nj", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "ћ": "ć", "у": "u",
    "ф": "f", "х": "h", "ц": "c", "ч": "č", "џ": "dž", "ш": "š",
}


def transliterate(text):
    out = []
    for i, ch in enumerate(text):
        lower = ch.lower()
        if lower not in CYR:
            out.append(ch)
            continue
        latin = CYR[lower]
        if ch != lower:  # uppercase: Љ -> Lj, or LJ inside an all-caps word
            following = text[i + 1] if i + 1 < len(text) else ""
            latin = latin.upper() if len(latin) > 1 and following.isupper() else latin[0].upper() + latin[1:]
        out.append(latin)
    return "".join(out)


def forms(localization):
    """Returns {variant: stringUnit} for a localization (plain -> {"": unit})."""
    if "stringUnit" in localization:
        return {"": localization["stringUnit"]}
    plural = localization.get("variations", {}).get("plural", {})
    return {name: variant.get("stringUnit", {}) for name, variant in plural.items()}


def check_catalog(path):
    errors = []
    with open(path, encoding="utf-8") as f:
        catalog = json.load(f)
    if catalog.get("sourceLanguage") != "en":
        errors.append(f"{path}: sourceLanguage is not en")
    for key, entry in catalog["strings"].items():
        locs = entry.get("localizations", {})
        sr, latn = locs.get("sr"), locs.get("sr-Latn")
        if sr is None or latn is None:
            errors.append(f"{key!r}: missing sr or sr-Latn")
            continue
        sr_forms, latn_forms = forms(sr), forms(latn)
        if set(sr_forms) != set(latn_forms):
            errors.append(f"{key!r}: sr and sr-Latn variants differ")
        if "" not in sr_forms and not SERBIAN_PLURALS <= set(sr_forms):
            errors.append(f"{key!r}: Serbian plural lacks one/few/other")
        for name, unit in sr_forms.items():
            other = latn_forms.get(name, {})
            for lang, u in (("sr", unit), ("sr-Latn", other)):
                if u.get("state") != "translated" or not u.get("value"):
                    errors.append(f"{key!r} [{lang} {name}]: not translated")
            if other.get("value") != transliterate(unit.get("value", "")):
                errors.append(f"{key!r} [{name}]: sr-Latn {other.get('value')!r} != "
                              f"transliteration {transliterate(unit.get('value', ''))!r}")
    return set(catalog["strings"]), errors


def extracted_keys(build, target):
    pattern = os.path.join(build, "Build/Intermediates.noindex", "*.build", "*", f"{target}.build",
                           "Objects-normal", "*", "*.stringsdata")
    keys = set()
    for path in glob.glob(pattern):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for entry in data.get("tables", {}).get("Localizable", []):
            keys.add(entry["key"])
    return keys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", help="xcodebuild derived data path to compare extracted keys")
    args = parser.parse_args()
    failed = False
    for target, path in CATALOGS.items():
        keys, errors = check_catalog(path)
        if args.build:
            extracted = extracted_keys(args.build, target)
            if not extracted:
                errors.append(f"no .stringsdata found for {target} under {args.build}")
            errors += [f"{k!r}: used in code but missing from catalog" for k in sorted(extracted - keys)]
            errors += [f"{k!r}: in catalog but not used in code" for k in sorted(keys - extracted)]
        print(f"{target}: {len(keys)} keys, {len(errors)} problem(s)")
        for error in errors:
            print("  - " + error)
        failed = failed or bool(errors)
    print("FAIL" if failed else "OK")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
