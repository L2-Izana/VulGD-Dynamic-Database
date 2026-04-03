import csv
import shutil
import zipfile
import neo4j
from urllib.request import urlopen
import os
from tqdm import tqdm
import xml.etree.ElementTree as ET
import re


def clean_text(text: str) -> str:
    """
    Clean text for CSV / Neo4j ingestion.
    - Remove newlines, tabs, carriage returns
    - Collapse repeated whitespace
    - Strip leading/trailing whitespace
    """
    if not text:
        return ""
    text = re.sub(r'[\r\n\t]+', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


class CWEPipeline:
    def __init__(self, neo4j_driver: neo4j.GraphDatabase.driver, data_dir="./datasource/"):
        self.neo4j_driver = neo4j_driver
        self.data_dir = data_dir
        self.cwe_data_dir = os.path.join(self.data_dir, "CWE")
        self.download_dir = os.path.join(self.cwe_data_dir, "cwec_latest.xml.zip")
        self.saved_df = os.path.join(self.cwe_data_dir, "WeaknessNodes.csv")
        self.old_data = os.path.join(self.data_dir, "WeaknessNodes.csv")
        self.url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
        os.makedirs(self.cwe_data_dir, exist_ok=True)

    def run(self):
        os.makedirs(os.path.dirname(self.download_dir), exist_ok=True)
        os.makedirs(os.path.dirname(self.saved_df), exist_ok=True)

        print(f"Downloading CWE dataset from {self.url}...")

        try:
            response = urlopen(self.url)
            total_size = int(response.info().get('Content-Length', 0))
            progress_bar = tqdm(total=total_size, unit='B', unit_scale=True, desc="Downloading")

            with open(self.download_dir, 'wb') as f:
                block_size = 8192
                while True:
                    buffer = response.read(block_size)
                    if not buffer:
                        break
                    f.write(buffer)
                    progress_bar.update(len(buffer))
            progress_bar.close()
            print(f"Download completed. File saved to {self.download_dir}")

            with zipfile.ZipFile(self.download_dir, 'r') as zip_ref:
                zip_ref.extractall(self.cwe_data_dir)
            print("Extraction completed successfully.")

            xml_files = [f for f in os.listdir(self.cwe_data_dir) if f.endswith('.xml')]
            if not xml_files:
                raise FileNotFoundError("No XML files found in the extracted directory")

            xml_filename = xml_files[0]
            xml_path = os.path.join(self.cwe_data_dir, xml_filename)
            print(f"Using XML file: {xml_path}")

            tree = ET.parse(xml_path)
            root = tree.getroot()

            namespaces = {'ns': 'http://cwe.mitre.org/cwe-7'}
            weaknesses = root.findall(".//ns:Weakness", namespaces)
            print(f"Found {len(weaknesses)} Weakness elements")

            weakness_list = [["cweID", "cweName", "weaknessAbstraction", "status", "description", "extendedDescription"]]

            for weakness in weaknesses:
                cwe_id = weakness.get("ID", "").strip()
                cwe_name = clean_text(weakness.get("Name", "").strip())
                abstraction = clean_text(weakness.get("Abstraction", "").strip())
                status = clean_text(weakness.get("Status", "").strip())

                desc_elem = weakness.find("ns:Description", namespaces)
                description = clean_text(desc_elem.text) if desc_elem is not None and desc_elem.text else ""

                ext_desc_elem = weakness.find("ns:Extended_Description", namespaces)
                extended_description_parts = []

                if ext_desc_elem is not None:
                    if ext_desc_elem.text:
                        extended_description_parts.append(ext_desc_elem.text)

                    for child in ext_desc_elem.iter():
                        if child is ext_desc_elem:
                            continue
                        if child.text:
                            extended_description_parts.append(child.text)
                        if child.tail:
                            extended_description_parts.append(child.tail)

                extended_description = clean_text(" ".join(extended_description_parts))

                weakness_list.append([
                    cwe_id,
                    cwe_name,
                    abstraction,
                    status,
                    description,
                    extended_description
                ])

            # Sort by cweID numerically from smallest to largest
            header = weakness_list[0]
            data_rows = weakness_list[1:]
            data_rows.sort(key=lambda x: int(x[0]) if str(x[0]).isdigit() else float('inf'))
            weakness_list = [header] + data_rows

            print(f"Writing {len(weakness_list) - 1} weaknesses to CSV: {self.saved_df}")
            with open(self.saved_df, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerows(weakness_list)

            print("CWE processing completed successfully.")
            return True

        except Exception as e:
            print(f"Error downloading or processing CWE data: {e}")
            import traceback
            traceback.print_exc()
            return False

    def migrate_data(self):
        """
        Compare newly downloaded CWE CSV (self.saved_df) with old master CSV (self.old_data),
        import only new cweID rows into Neo4j, then merge both files into self.old_data
        and delete self.saved_df to save storage.
        """
        if not self.neo4j_driver:
            print("No Neo4j driver found. Please initialize the pipeline with a Neo4j driver.")
            return False

        try:
            if not os.path.exists(self.saved_df):
                print(f"New CWE file not found: {self.saved_df}")
                return False

            print(f"Reading new CWE data from {self.saved_df}")

            # ----------------------------
            # Step 1: Load old existing data
            # ----------------------------
            old_rows_by_id = {}
            header = ["cweID", "cweName", "weaknessAbstraction", "status", "description", "extendedDescription"]

            if os.path.exists(self.old_data):
                print(f"Reading old CWE data from {self.old_data}")
                with open(self.old_data, "r", encoding="utf-8") as old_file:
                    reader = csv.reader(old_file)
                    old_header = next(reader, None)

                    # keep old header if present and valid
                    if old_header and len(old_header) >= 6:
                        header = old_header[:6]

                    for row in reader:
                        if len(row) < 6:
                            continue
                        cwe_id = row[0].strip()
                        if not cwe_id:
                            continue
                        old_rows_by_id[cwe_id] = row[:6]
            else:
                print(f"No old CWE file found. A new master file will be created at: {self.old_data}")

            old_ids = set(old_rows_by_id.keys())

            # ----------------------------
            # Step 2: Load new downloaded data
            # ----------------------------
            new_rows_by_id = {}
            with open(self.saved_df, "r", encoding="utf-8") as new_file:
                reader = csv.reader(new_file)
                new_header = next(reader, None)

                if new_header and len(new_header) >= 6:
                    header = new_header[:6]

                for row in reader:
                    if len(row) < 6:
                        print(f"Skipping incomplete new row: {row}")
                        continue

                    cwe_id = row[0].strip()
                    if not cwe_id:
                        print(f"Skipping row with empty cweID: {row}")
                        continue

                    cleaned_row = [
                        cwe_id,
                        clean_text(row[1]),
                        clean_text(row[2]),
                        clean_text(row[3]),
                        clean_text(row[4]),
                        clean_text(row[5]),
                    ]
                    new_rows_by_id[cwe_id] = cleaned_row

            new_ids = set(new_rows_by_id.keys())

            # ----------------------------
            # Step 3: Find truly new CWE IDs
            # ----------------------------
            added_ids = sorted(
                list(new_ids - old_ids),
                key=lambda x: int(x) if str(x).isdigit() else float("inf")
            )

            print(f"Found {len(added_ids)} new CWE IDs")

            # ----------------------------
            # Step 4: Import only new rows into Neo4j
            # ----------------------------
            batch_size = 100
            current_batch = []
            total_processed = 0

            for cwe_id in added_ids:
                row = new_rows_by_id[cwe_id]

                current_batch.append({
                    "cweID": row[0],
                    "cweName": row[1],
                    "weaknessAbstraction": row[2],
                    "status": row[3],
                    "description": row[4],
                    "extendedDescription": row[5],
                })

                if len(current_batch) >= batch_size:
                    self._process_weakness_batch(current_batch)
                    total_processed += len(current_batch)
                    print(f"Processed {total_processed} new weaknesses into Neo4j")
                    current_batch = []

            if current_batch:
                self._process_weakness_batch(current_batch)
                total_processed += len(current_batch)

            print(f"Neo4j migration complete: {total_processed} new CWE weaknesses imported")

            # ----------------------------
            # Step 5: Merge old + new into one master CSV
            # Rule:
            # - keep all old rows
            # - overwrite with new row if same cweID exists in new file
            # - include brand new rows
            # ----------------------------
            merged_rows_by_id = dict(old_rows_by_id)
            merged_rows_by_id.update(new_rows_by_id)

            merged_rows = list(merged_rows_by_id.values())
            merged_rows.sort(key=lambda row: int(row[0]) if str(row[0]).isdigit() else float("inf"))

            print(f"Writing merged CWE master file to {self.old_data}")
            with open(self.old_data, "w", newline="", encoding="utf-8") as merged_file:
                writer = csv.writer(merged_file)
                writer.writerow(header)
                writer.writerows(merged_rows)

            print(f"Merged master file contains {len(merged_rows)} total CWE rows")

            # ----------------------------
            # Step 6: Delete temporary new file for storage saving
            # ----------------------------
            if os.path.exists(self.saved_df):
                os.remove(self.saved_df)
                print(f"Deleted temporary new CWE file: {self.saved_df}")

            return True

        except Exception as e:
            print(f"Error during migration: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _process_weakness_batch(self, batch):
        """
        Process a batch of weakness entries to import into Neo4j

        Args:
            batch: List of dictionaries containing weakness data
        """
        with self.neo4j_driver.session() as session:
            for weakness in batch:
                try:
                    session.run("""
                    MERGE (w:Weakness {cweID: $cweID})
                    SET w.cweName = $cweName,
                        w.weaknessAbstraction = $weaknessAbstraction,
                        w.status = $status,
                        w.description = $description,
                        w.extendedDescription = $extendedDescription
                    """, weakness)
                except Exception as e:
                    print(f"Error processing weakness {weakness.get('cweID')}: {e}")



# usage

if __name__ == "__main__":
    driver = neo4j.GraphDatabase.driver(
        "bolt://localhost:7687",
        auth=("neo4j", "Vanly180705!")
    )
    assert_neo4j_connection(driver)
    cwe_pipeline = CWEPipeline(driver)
    cwe_pipeline.run()
    cwe_pipeline.migrate_data()