import os
import sys
import time
from urllib.request import urlopen
from urllib.error import HTTPError, URLError
from bs4 import BeautifulSoup
from loguru import logger
import neo4j
import pandas as pd


# ----------------------------
# Loguru configuration
# ----------------------------
os.makedirs("logs", exist_ok=True)

logger.remove()

logger.add(
    sys.stdout,
    level="INFO",
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | {message}",
    colorize=True,
)

logger.add(
    "logs/edb_pipeline.log",
    level="DEBUG",
    rotation="50 MB",
    retention="10 days",
    encoding="utf-8",
    format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} | {message}",
    backtrace=True,
    diagnose=True,
)


class EDBPipeline:
    def __init__(self, neo4j_driver: neo4j.GraphDatabase.driver):
        self.neo4j_driver = neo4j_driver
        self.saved_df = "./datasource/ExploitNodes.csv"
        self.base_url = "https://www.exploit-db.com/exploits/"
        self.current_page_number = self._get_start_page_from_csv()

        logger.info("Initialized EDBPipeline")
        logger.info(f"CSV path: {self.saved_df}")
        logger.info(f"Starting exploit page: {self.current_page_number}")

    def _get_start_page_from_csv(self):
        """
        Determine the starting exploit page directly from the last non-empty line
        of ExploitNodes.csv.

        Example last row:
        EXPLOIT-DB:49546,2021-02-09,NavedShaikh,webapps,PHP

        -> next page should start from 49547
        """
        if not os.path.exists(self.saved_df):
            logger.info("CSV file does not exist yet. Starting from exploit page 1.")
            return 1

        try:
            last_line = None
            with open(self.saved_df, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped

            if not last_line:
                logger.warning("CSV file exists but is empty. Starting from exploit page 1.")
                return 1

            if last_line.startswith("eid,"):
                logger.info("CSV only contains header. Starting from exploit page 1.")
                return 1

            first_col = last_line.split(",", 1)[0].strip().strip('"')

            if not first_col.startswith("EXPLOIT-DB:"):
                logger.warning(f"Unexpected last row format: {last_line}")
                logger.warning("Falling back to exploit page 1.")
                return 1

            exploit_id = int(first_col.replace("EXPLOIT-DB:", ""))
            start_page = exploit_id + 1
            logger.info(f"Resuming from exploit page {start_page} based on last CSV row: {last_line}")
            return start_page

        except Exception:
            logger.exception("Failed to determine start page from CSV. Falling back to exploit page 1.")
            return 1

    def _fetch_page_content(self, exploit_id: int):
        """
        Fetch a page by exploit ID.

        Returns:
            str: HTML content if successful
            None: if page is 404 and should be skipped

        Raises:
            Exception: for non-404 errors
        """
        page_url = self.base_url + str(exploit_id)
        logger.info(f"[PAGE {exploit_id}] Crawling {page_url}")

        try:
            with urlopen(page_url) as page:
                return page.read().decode("utf-8")

        except HTTPError as e:
            if e.code == 404:
                logger.warning(f"[PAGE {exploit_id}] 404 Not Found -> skipping")
                return None

            logger.error(f"[PAGE {exploit_id}] HTTP error {e.code}: {e.reason}")
            raise

        except URLError as e:
            logger.error(f"[PAGE {exploit_id}] URL error: {e}")
            raise

        except Exception:
            logger.exception(f"[PAGE {exploit_id}] Unexpected fetch error")
            raise

    def run(self):
        csv_header = ["eid", "exploitPublishDate", "author", "exploitType", "platform"]

        os.makedirs(os.path.dirname(self.saved_df), exist_ok=True)

        csv_list = []
        if not os.path.exists(self.saved_df):
            with open(self.saved_df, "w", encoding="utf-8") as f:
                f.write(",".join(csv_header) + "\n")
            logger.info(f"Created new CSV file with header: {self.saved_df}")

        rows_processed = 0
        batch_size = 50
        max_consecutive_404 = 100
        consecutive_404_count = 0

        logger.info("Starting crawl loop")

        while True:
            try:
                content = self._fetch_page_content(self.current_page_number)

                # Missing exploit ID: normal case, just skip
                if content is None:
                    consecutive_404_count += 1

                    if consecutive_404_count >= max_consecutive_404:
                        logger.warning(
                            f"Encountered {consecutive_404_count} consecutive 404 pages. "
                            "Assuming end of available exploits and stopping crawl."
                        )
                        break

                    self.current_page_number += 1
                    # time.sleep(0.2)
                    continue

                # Successful fetch resets consecutive 404 count
                consecutive_404_count = 0

                soup = BeautifulSoup(content, "html.parser")
                tags = soup.find_all("h6", class_="stats-title")

                if len(tags) < 6:
                    logger.warning(
                        f"[PAGE {self.current_page_number}] "
                        f"Not enough stats-title tags found ({len(tags)}). Skipping page."
                    )
                    self.current_page_number += 1
                    # time.sleep(0.2)
                    continue

                try:
                    edbid = "EXPLOIT-DB:" + self._clean_text(tags[0].get_text().strip())
                    author = self._clean_text(tags[2].get_text().strip())
                    exploit_type = self._clean_text(tags[3].get_text().strip())
                    platform = self._clean_text(tags[4].get_text().strip())
                    exploit_date = self._clean_text(tags[5].get_text().strip())

                    csv_item = [edbid, exploit_date, author, exploit_type, platform]
                    csv_list.append(csv_item)
                    rows_processed += 1

                    logger.debug(
                        f"[PAGE {self.current_page_number}] Parsed exploit: "
                        f"eid={edbid}, date={exploit_date}, author={author}, "
                        f"type={exploit_type}, platform={platform}"
                    )

                except Exception:
                    logger.exception(f"[PAGE {self.current_page_number}] Error processing page contents")
                    self.current_page_number += 1
                    # time.sleep(0.2)
                    continue

                if len(csv_list) >= batch_size:
                    self._write_csv_batch(csv_list)
                    csv_list = []
                    logger.info(f"Checkpoint: {rows_processed} total new rows processed")

                self.current_page_number += 1
                # time.sleep(0.2)

            except KeyboardInterrupt:
                logger.warning("KeyboardInterrupt received. Stopping crawl gracefully.")
                break

            except Exception:
                logger.exception(
                    f"[PAGE {self.current_page_number}] Fatal error during crawl loop. Stopping crawl."
                )
                break

        if csv_list:
            self._write_csv_batch(csv_list)

        logger.success(f"Data saved to {self.saved_df}. Total new records processed: {rows_processed}")

    def _clean_text(self, text):
        """Clean and normalize text to prevent encoding and CSV issues."""
        if not text:
            return ""

        text = text.replace(" ", "")
        text = "".join(c for c in text if c.isprintable())
        text = text.replace('"', '""')
        return text

    def _write_csv_batch(self, csv_list):
        """Write a batch of data to CSV with proper encoding handling."""
        logger.info(f"Writing batch of {len(csv_list)} rows to CSV: {self.saved_df}")

        with open(self.saved_df, "a", encoding="utf-8", errors="replace") as f:
            for row in csv_list:
                quoted_items = [f'"{value}"' if "," in value else value for value in row]
                f.write(",".join(quoted_items) + "\n")

        logger.debug("Batch write completed")

    def migrate_data(self):
        """
        Migrates the EDB exploit data to Neo4j, handling potential encoding issues.
        Skips rows with unexpected column counts instead of failing.
        """
        if not self.neo4j_driver:
            logger.error("No Neo4j driver found. Please initialize the pipeline with a Neo4j driver.")
            return False

        try:
            logger.info(f"Reading CSV data from {self.saved_df}")

            try:
                df = pd.read_csv(self.saved_df, encoding="utf-8", on_bad_lines="skip", low_memory=False)
                logger.info("Loaded CSV using pandas with on_bad_lines='skip'")
            except TypeError:
                df = pd.read_csv(
                    self.saved_df,
                    encoding="utf-8",
                    error_bad_lines=False,
                    warn_bad_lines=True,
                    low_memory=False,
                )
                logger.info("Loaded CSV using pandas with error_bad_lines=False")

            if df.empty:
                logger.warning("No data could be read from the CSV file.")
                return False

            logger.info(f"Successfully read {len(df)} rows from CSV with {df.shape[1]} columns")

            corrected_columns_names = ["eid", "exploitPublishDate", "author", "exploitType", "platform"]

            if df.shape[1] != len(corrected_columns_names):
                logger.warning(
                    f"CSV has {df.shape[1]} columns, expected {len(corrected_columns_names)}. Attempting correction."
                )

                if df.shape[1] > len(corrected_columns_names):
                    df = df.iloc[:, :len(corrected_columns_names)]
                    logger.warning(f"Trimmed DataFrame to {len(corrected_columns_names)} columns.")

                while df.shape[1] < len(corrected_columns_names):
                    df[f"empty_{df.shape[1]}"] = ""
                    logger.warning(f"Added empty column index {df.shape[1] - 1}")

            df.columns = corrected_columns_names

            text_columns = ["eid", "author", "exploitType", "platform"]
            for col in text_columns:
                if col in df.columns:
                    df[col] = df[col].astype(str).apply(
                        lambda x: "".join(c for c in x if c.isprintable())
                    )

            logger.info("Converting data types to match Neo4j expectations")

            try:
                df["exploitPublishDate"] = pd.to_datetime(
                    df["exploitPublishDate"], errors="coerce"
                ).dt.strftime("%Y-%m-%d")
                df["exploitPublishDate"] = df["exploitPublishDate"].fillna("2000-01-01")
            except Exception:
                logger.exception("Error converting exploitPublishDate. Using default date 2000-01-01.")
                df["exploitPublishDate"] = "2000-01-01"

            batch_size = 1000
            total_rows = len(df)

            logger.info("Migrating Exploit and Author nodes...")
            for i in range(0, total_rows, batch_size):
                end_idx = min(i + batch_size, total_rows)
                batch = df.iloc[i:end_idx]

                with self.neo4j_driver.session() as session:
                    for _, row in batch.iterrows():
                        try:
                            if pd.isna(row["eid"]) or not row["eid"]:
                                logger.warning(f"Skipping row with missing eid: {row.to_dict()}")
                                continue

                            session.run(
                                "MERGE (e:Exploit {eid: $eid}) "
                                "SET e.exploitPublishDate = date($exploitPublishDate), "
                                "    e.exploitType = $exploitType, "
                                "    e.platform = $platform",
                                {
                                    "eid": row["eid"],
                                    "exploitPublishDate": row["exploitPublishDate"],
                                    "exploitType": row["exploitType"],
                                    "platform": row["platform"],
                                },
                            )

                            if not pd.isna(row["author"]) and row["author"]:
                                session.run(
                                    "MERGE (a:Author {authorName: $author}) "
                                    "SET a.authorName = $author",
                                    {"author": row["author"]},
                                )

                        except Exception:
                            logger.error(f"Failed row during node migration: {row.to_dict()}")
                            logger.exception("Neo4j node write error")

                logger.info(f"Processed {end_idx}/{total_rows} rows for Exploit and Author nodes")

            logger.info("Creating WRITES relationships...")
            for i in range(0, total_rows, batch_size):
                end_idx = min(i + batch_size, total_rows)
                batch = df.iloc[i:end_idx]

                with self.neo4j_driver.session() as session:
                    for _, row in batch.iterrows():
                        try:
                            if (
                                pd.isna(row["eid"])
                                or pd.isna(row["author"])
                                or not row["eid"]
                                or not row["author"]
                            ):
                                continue

                            session.run(
                                "MATCH (e:Exploit {eid: $eid}) "
                                "MATCH (a:Author {authorName: $author}) "
                                "MERGE (a)-[:WRITES]->(e)",
                                {"eid": row["eid"], "author": row["author"]},
                            )

                        except Exception:
                            logger.error(
                                f"Failed relationship creation for eid={row.get('eid')} author={row.get('author')}"
                            )
                            logger.exception("Neo4j relationship write error")

                logger.info(f"Processed {end_idx}/{total_rows} rows for WRITES relationships")

            logger.success("Migration completed successfully")
            return True

        except Exception:
            logger.exception("Error during migration")
            return False


if __name__ == "__main__":
    driver = None
    try:
        logger.info("Initializing Neo4j driver")
        driver = neo4j.GraphDatabase.driver(
            "bolt://localhost:7687",
            auth=("neo4j", "Vanly180705!")
        )

        # Optional connectivity check
        # logger.info("Testing Neo4j connectivity")
        # driver.verify_connectivity()
        # logger.success("Neo4j connection successful")

        edb_pipeline = EDBPipeline(neo4j_driver=driver)

        logger.info("Running crawler")
        edb_pipeline.run()

        # Uncomment if you want migration immediately after crawling
        # logger.info("Running migration")
        # if edb_pipeline.migrate_data():
        #     logger.success("Data migrated successfully!")
        # else:
        #     logger.error("Data migration failed.")

    except Exception:
        logger.exception("Fatal error in main execution")

    finally:
        if driver is not None:
            driver.close()
            logger.info("Neo4j driver closed")