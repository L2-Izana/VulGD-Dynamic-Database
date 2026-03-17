import pandas as pd
import re
import csv
import argparse
from pathlib import Path

# -------- argument parsing --------
parser = argparse.ArgumentParser(
    description="Clean VulnerabilityNodes CSV for Neo4j import"
)
parser.add_argument(
    "datadir",
    type=str,
    help="Directory containing VulnerabilityNodes.csv"
)

args = parser.parse_args()
DATADIR = Path(args.datadir)

INPUT = DATADIR / "VulnerabilityNodes.csv"
OUTPUT = DATADIR / "VulnerabilityNodes_clean.csv"

# -------- expected schema (STRICT) --------
EXPECTED_COLUMNS = [
    'cveID', 'publishedDate', 'description_value', 'num_reference',
    'v2version', 'v2baseScore', 'v2accessVector', 'v2accessComplexity',
    'v2authentication', 'v2confidentialityImpact', 'v2integrityImpact',
    'v2availabilityImpact', 'v2vectorString', 'v2impactScore',
    'v2exploitabilityScore', 'v2userInteractionRequired', 'v2severity',
    'v2obtainUserPrivilege', 'v2obtainAllPrivilege', 'v2acInsufInfo',
    'v2obtainOtherPrivilege', 'v3version', 'v3baseScore', 'v3attackVector',
    'v3attackComplexity', 'v3privilegesRequired', 'v3userInteraction',
    'v3scope', 'v3confidentialityImpact', 'v3integrityImpact',
    'v3availabilityImpact', 'v3vectorString', 'v3impactScore',
    'v3exploitabilityScore', 'v3baseSeverity'
]

# -------- load csv (skip broken rows) --------
df = pd.read_csv(
    INPUT,
    dtype=str,
    keep_default_na=False,
    engine="python",
    on_bad_lines="skip"   # 🔥 CRITICAL
)

print(f"[INFO] Loaded rows: {len(df)}")

# -------- enforce schema --------
df = df.reindex(columns=EXPECTED_COLUMNS)
df.fillna("", inplace=True)

# -------- text cleaning --------
def clean_text(x):
    if not isinstance(x, str):
        return ""

    x = x.replace("\n", " ").replace("\r", " ")
    x = x.replace('"', "'")
    x = x.replace("\\", "/")

    # remove control chars
    x = re.sub(r"[\x00-\x1f\x7f]", " ", x)

    # IMPORTANT: remove delimiter conflicts
    x = x.replace(",", ";")

    x = re.sub(r"\s+", " ", x)

    return x.strip()

for col in df.columns:
    df[col] = df[col].apply(clean_text)

# -------- type normalization --------
INT_COLS = ['num_reference', 'v2version']
FLOAT_COLS = [
    'v2baseScore', 'v2impactScore', 'v2exploitabilityScore',
    'v3baseScore', 'v3impactScore', 'v3exploitabilityScore'
]

for col in INT_COLS:
    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)

for col in FLOAT_COLS:
    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)

# -------- write strict CSV --------
df.to_csv(
    OUTPUT,
    index=False,
    quoting=csv.QUOTE_ALL,
    escapechar="\\",
    lineterminator="\n"
)

print(f"[INFO] Clean CSV written to: {OUTPUT}")

# -------- validation (CRITICAL) --------
print("[INFO] Validating CSV structure...")

with open(OUTPUT, encoding="utf-8") as f:
    header_len = len(f.readline().strip().split(","))
    for i, line in enumerate(f, start=2):
        if len(line.strip().split(",")) != header_len:
            print(f"[ERROR] Broken row at line {i}")
            break
    else:
        print("[SUCCESS] CSV structure is valid ✅")