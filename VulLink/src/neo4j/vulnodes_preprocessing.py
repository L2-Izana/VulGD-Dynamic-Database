import pandas as pd
import re
import csv
import argparse
from pathlib import Path

# -------- argument parsing --------
parser = argparse.ArgumentParser(description="Clean VulnerabilityNodes CSV for Neo4j import")
parser.add_argument(
    "datadir",
    type=str,
    help="Directory containing VulnerabilityNodes.csv"
)

args = parser.parse_args()
DATADIR = Path(args.datadir)

# -------- load csv --------
df = pd.read_csv(
    DATADIR / "VulnerabilityNodes.csv",
    dtype=str,
    keep_default_na=False,
    engine="python"   # tolerant parser
)

def clean_text(x):
    if not isinstance(x, str):
        return ""

    # remove newline / carriage return
    x = x.replace("\n", " ").replace("\r", " ")

    # remove unescaped quotes
    x = x.replace('"', "'")

    # remove weird control characters
    x = re.sub(r"[\x00-\x1f\x7f]", " ", x)

    # normalize whitespace
    x = re.sub(r"\s+", " ", x)

    return x.strip()

# clean description
df["description_value"] = df["description_value"].apply(clean_text)

# sanitize vector strings
for col in ["v2vectorString", "v3vectorString"]:
    if col in df.columns:
        df[col] = df[col].apply(clean_text)

# -------- write cleaned csv --------
df.to_csv(
    DATADIR / "VulnerabilityNodes_clean.csv",
    index=False,
    quoting=csv.QUOTE_ALL,
    escapechar="\\"
)