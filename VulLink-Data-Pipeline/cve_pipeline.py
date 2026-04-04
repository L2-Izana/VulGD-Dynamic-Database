import os
import re
import csv
import neo4j
from urllib.request import urlopen
from bs4 import BeautifulSoup
from loguru import logger


class CVEPipeline:
    def __init__(self, neo4j_driver: neo4j.GraphDatabase.driver):
        self.neo4j_driver = neo4j_driver
        os.makedirs("./datasource", exist_ok=True)
        self.saved_df = "./datasource/Vulnerability_HAS_EXPLOIT_Exploit_relationship.csv"

    @staticmethod
    def _clean_text(text: str) -> str:
        if text is None:
            return ""
        return re.sub(r"\s+", " ", str(text)).strip()

    @staticmethod
    def _extract_exploit_id(text: str):
        text = CVEPipeline._clean_text(text)
        match = re.search(r"EXPLOIT-DB:(\d+)", text, flags=re.IGNORECASE)
        if not match:
            return None
        return f"EXPLOIT-DB:{int(match.group(1))}"

    @staticmethod
    def _extract_cve_ids(text: str) -> list[str]:
        text = CVEPipeline._clean_text(text)
        cve_ids = re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)

        cleaned = []
        for cve_id in cve_ids:
            cve_id = cve_id.strip().upper()
            if not cve_id:
                continue
            if cve_id.lower() == "nan":
                continue
            cleaned.append(cve_id)

        return sorted(set(cleaned))

    @staticmethod
    def _exploit_sort_key(eid: str) -> int:
        match = re.search(r"EXPLOIT-DB:(\d+)", eid)
        return int(match.group(1)) if match else float("inf")

    def _load_existing_pairs(self) -> set[tuple[str, str]]:
        pairs = set()

        if not os.path.exists(self.saved_df):
            logger.info(f"No existing CSV found at {self.saved_df}. Starting fresh.")
            return pairs

        logger.info(f"Loading existing CSV from {self.saved_df}")

        with open(self.saved_df, "r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, None)

            for row in reader:
                if len(row) < 2:
                    continue

                eid = self._extract_exploit_id(row[0])
                cve_id = self._clean_text(row[1]).upper()

                if not eid:
                    continue
                if not cve_id or cve_id.lower() == "nan":
                    continue
                if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve_id, flags=re.IGNORECASE):
                    continue

                pairs.add((eid, cve_id))

        logger.info(f"Loaded {len(pairs)} existing valid exploit-CVE pairs")
        return pairs

    def _crawl_new_pairs(self) -> set[tuple[str, str]]:
        url = "https://www.cve.org/Resources/Media/Archives/OldWebsite/data/refs/refmap/source-EXPLOIT-DB.html"
        logger.info(f"Fetching {url}")

        html = urlopen(url)
        bs_obj = BeautifulSoup(html, features="lxml")

        tables = bs_obj.find_all("table")
        if len(tables) < 4:
            raise RuntimeError(f"Expected at least 4 tables, found {len(tables)}")

        table = tables[3]
        rows = table.find_all("tr")

        pairs: set[tuple[str, str]] = set()

        for row in rows:
            cells = row.find_all("td")
            if len(cells) < 2:
                continue

            raw_eid = cells[0].get_text(" ", strip=True)
            raw_cve = cells[1].get_text(" ", strip=True)

            eid = self._extract_exploit_id(raw_eid)
            if not eid:
                continue

            cve_ids = self._extract_cve_ids(raw_cve)
            if not cve_ids:
                continue

            for cve_id in cve_ids:
                if not cve_id or cve_id.lower() == "nan":
                    continue
                pairs.add((eid, cve_id))

        logger.info(f"Crawled {len(pairs)} new valid exploit-CVE pairs")
        return pairs

    def run(self):
        old_pairs = self._load_existing_pairs()
        new_pairs = self._crawl_new_pairs()

        combined_pairs = sorted(
            old_pairs | new_pairs,
            key=lambda x: (self._exploit_sort_key(x[0]), x[1])
        )

        logger.info(
            f"Writing merged CSV to {self.saved_df}. "
            f"old={len(old_pairs)}, new={len(new_pairs)}, merged_unique={len(combined_pairs)}"
        )

        with open(self.saved_df, "w", newline="", encoding="utf-8") as csvwf:
            writer = csv.writer(csvwf)
            writer.writerow(["eid", "cveID"])
            writer.writerows(combined_pairs)

        logger.info("CSV export complete.")
        print(f"the number of items in the output file: {len(combined_pairs) + 1}")

    def migrate_data(self):
        try:
            with self.neo4j_driver.session() as session:
                with open(self.saved_df, 'r') as csv_file:
                    reader = csv.reader(csv_file)
                    next(reader)  # Skip header row
                    batch_size = 1000
                    batch = []
                    
                    for row in reader:
                        if len(row) < 2:
                            print(f"Skipping invalid row: {row}")
                            continue
                            
                        eid = row[0]
                        cveID = row[1]
                        
                        # Add to batch
                        batch.append((eid, cveID))
                        
                        # Process in batches to improve performance
                        if len(batch) >= batch_size:
                            self._process_batch(session, batch)
                            batch = []
                    
                    # Process any remaining items
                    if batch:
                        self._process_batch(session, batch)
                    
                return True
        except Exception as e:
            print(f"Error during migration: {e}")
            import traceback
            traceback.print_exc()  # Print the full traceback for debugging
            return False

    def _process_batch(self, session, batch):
        """Process a batch of relationship creations"""
        print(f"Processing batch of {len(batch)} relationships...")
        try:
            count = 0
            for eid, cveID in batch:
                # The key fix: properly pass parameters to the query
                session.run(
                    "MATCH (e:Exploit {eid: $eid}) "
                    "MATCH (v:Vulnerability {cveID: $cveID}) "
                    "MERGE (e)-[:EXPLOITS]->(v)",
                    {"eid": eid, "cveID": cveID}  # This is what was missing
                )
                count += 1
                
                # Print progress every 100 items
                if count % 100 == 0:
                    print(f"Processed {count} relationships in current batch")
                
        except Exception as e:
            print(f"Error in batch processing: {e}")
            # Continue with the next batch despite errors

if __name__ == "__main__":
    driver = neo4j.GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Vanly180705!"))
    cve_pipeline = CVEPipeline(driver)
    cve_pipeline.run()
    # cve_pipeline.migrate_data()





