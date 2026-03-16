import os
import pandas as pd

src_dir = r"data\vulkg"
dst_dir = r"data\dummy_vulkg"

os.makedirs(dst_dir, exist_ok=True)

for file in os.listdir(src_dir):
    if file.endswith(".csv"):
        src_path = os.path.join(src_dir, file)
        dst_path = os.path.join(dst_dir, file)

        df = pd.read_csv(src_path, nrows=100)
        df.to_csv(dst_path, index=False)

        print(f"Created {dst_path} with {len(df)} rows")

print("Done.")