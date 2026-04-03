import json
import os
import re
import zipfile
from typing import List, Optional

import neo4j
import pandas as pd
import wget
from loguru import logger

from utils import assert_neo4j_connection


class NVDPipeline:
    """
    NVD 2.0 -> legacy 35-column company schema -> Neo4j migration
    """

    LEGACY_COLUMNS = [
        "cveID",
        "publishedDate",
        "description_value",
        "num_reference",
        "v2version",
        "v2baseScore",
        "v2accessVector",
        "v2accessComplexity",
        "v2authentication",
        "v2confidentialityImpact",
        "v2integrityImpact",
        "v2availabilityImpact",
        "v2vectorString",
        "v2impactScore",
        "v2exploitabilityScore",
        "v2userInteractionRequired",
        "v2severity",
        "v2obtainUserPrivilege",
        "v2obtainAllPrivilege",
        "v2acInsufInfo",
        "v2obtainOtherPrivilege",
        "v3version",
        "v3baseScore",
        "v3attackVector",
        "v3attackComplexity",
        "v3privilegesRequired",
        "v3userInteraction",
        "v3scope",
        "v3confidentialityImpact",
        "v3integrityImpact",
        "v3availabilityImpact",
        "v3vectorString",
        "v3impactScore",
        "v3exploitabilityScore",
        "v3baseSeverity",
    ]

    CSV_COLUMNS = [
        "cveID",
        "publishedDate",
        "description",
        "numOfReference",
        "v2version",
        "v2baseScore",
        "v2accessVector",
        "v2accessComplexity",
        "v2authentication",
        "v2confidentialityImpact",
        "v2integrityImpact",
        "v2availabilityImpact",
        "v2vectorString",
        "v2impactScore",
        "v2exploitabilityScore",
        "v2userInteractionRequired",
        "v2severity",
        "v2obtainUserPrivilege",
        "v2obtainAllPrivilege",
        "v2acInsufInfo",
        "v2obtainOtherPrivilege",
        "v3version",
        "v3baseScore",
        "v3attackVector",
        "v3attackComplexity",
        "v3privilegesRequired",
        "v3userInteraction",
        "v3scope",
        "v3confidentialityImpact",
        "v3integrityImpact",
        "v3availabilityImpact",
        "v3vectorString",
        "v3impactScore",
        "v3exploitabilityScore",
        "v3baseSeverity",
    ]

    def __init__(self, neo4j_driver: neo4j.GraphDatabase.driver):
        self.neo4j_driver = neo4j_driver
        self.output_dir = "./datasource/NVD"
        self.combined_parsed_saved_df = "./datasource/VulnerabilityNodes.csv"
        self._setup_logger()

    def _setup_logger(self) -> None:
        os.makedirs("./logs", exist_ok=True)
        logger.remove()
        logger.add(
            lambda msg: print(msg, end=""),
            format=(
                "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
                "<level>{level: <8}</level> | "
                "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
                "<level>{message}</level>"
            ),
        )
        logger.add(
            "./logs/nvd_pipeline.log",
            rotation="10 MB",
            retention=5,
            enqueue=True,
            encoding="utf-8",
            level="INFO",
        )

    def get_existing_json_files(self) -> List[str]:
        os.makedirs(self.output_dir, exist_ok=True)
        return sorted(
            os.path.join(self.output_dir, fname)
            for fname in os.listdir(self.output_dir)
            if fname.lower().endswith(".json")
        )

    def crawl_nvd_data(self) -> List[str]:
        """
        Reuse local JSON files if they already exist.
        Otherwise download NVD 2.0 feed archives and extract them.
        """
        existing_json_files = self.get_existing_json_files()
        if existing_json_files:
            logger.info(
                f"Found {len(existing_json_files)} existing JSON files in {self.output_dir}. "
                "Skipping crawl and reusing local files."
            )
            for path in existing_json_files:
                logger.info(f"Reusing local file: {path}")
            return existing_json_files

        os.makedirs(self.output_dir, exist_ok=True)

        base_urls = [
            "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.zip",
            "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.zip",
        ]
        for year in range(2002, 2027):
            base_urls.append(f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.zip")

        logger.info(f"Starting download of {len(base_urls)} NVD feed archives...")

        for link_url in base_urls:
            try:
                logger.info(f"Downloading: {link_url}")
                downloaded_zip_path = wget.download(link_url, out=self.output_dir)
                print()  # keep wget output readable

                logger.info(f"Downloaded archive: {downloaded_zip_path}")

                if downloaded_zip_path.lower().endswith(".zip"):
                    with zipfile.ZipFile(downloaded_zip_path, "r") as zip_ref:
                        zip_ref.extractall(self.output_dir)
                    os.remove(downloaded_zip_path)
                    logger.info(f"Extracted and removed archive: {downloaded_zip_path}")

            except Exception as e:
                logger.exception(f"Failed to download {link_url}: {e}")

        json_files = self.get_existing_json_files()
        if not json_files:
            raise RuntimeError("No JSON files were downloaded from NVD.")

        logger.info(f"Collected {len(json_files)} JSON files after download.")
        for path in json_files:
            logger.info(f"JSON file: {path}")

        return json_files

    def preprocess_files(self, json_files: List[str]) -> pd.DataFrame:
        if not json_files:
            raise RuntimeError("No JSON files to process.")

        logger.info("Parsing JSON files...")
        parsed_dataframes: List[pd.DataFrame] = []

        for json_path in json_files:
            try:
                df = self._parse_single_json_to_df(json_path)
                logger.info(f"Parsed {json_path} -> shape={df.shape}")
                if df is not None and not df.empty:
                    parsed_dataframes.append(df)
                else:
                    logger.warning(f"Skipping empty DataFrame from {json_path}")
            except Exception as e:
                logger.exception(f"Failed parsing {json_path}: {e}")

        if not parsed_dataframes:
            raise RuntimeError("No DataFrames were created. Nothing to combine.")

        combined_df = pd.concat(parsed_dataframes, ignore_index=True)
        logger.info(
            f"Combined {len(parsed_dataframes)} DataFrames. "
            f"Shape before deduplication: {combined_df.shape}"
        )

        before_count = len(combined_df)
        combined_df = combined_df.drop_duplicates(subset=["cveID"], keep="last")
        after_count = len(combined_df)

        logger.info(
            f"Removed {before_count - after_count} duplicate rows. "
            f"Final row count: {after_count}"
        )

        combined_df = self._final_processing(combined_df)
        combined_df = self._ensure_legacy_schema(combined_df)
        return combined_df

    def _ensure_legacy_schema(self, df: pd.DataFrame) -> pd.DataFrame:
        for col in self.LEGACY_COLUMNS:
            if col not in df.columns:
                df[col] = None

        extra_cols = [c for c in df.columns if c not in self.LEGACY_COLUMNS]
        if extra_cols:
            logger.warning(f"Dropping unexpected columns: {extra_cols}")

        df = df[self.LEGACY_COLUMNS].copy()
        logger.info(f"Schema normalized to legacy 35-column format. Shape: {df.shape}")
        return df

    def validate_data(self, df: pd.DataFrame) -> bool:
        if df is None or df.empty:
            logger.error("Validation failed: DataFrame is empty.")
            return False

        if list(df.columns) != self.LEGACY_COLUMNS:
            logger.error(
                f"Invalid schema. Expected {len(self.LEGACY_COLUMNS)} columns, got {len(df.columns)}"
            )
            logger.error(f"Actual columns: {list(df.columns)}")
            return False

        if df["cveID"].isnull().any() or (df["cveID"].astype(str).str.strip() == "").any():
            logger.error("Validation failed: missing or blank cveID found.")
            return False

        cleaned_desc = df["description_value"].apply(self._clean_description)

        if cleaned_desc.fillna("").str.slice(0, 15).str.contains("REJECT", na=False, case=False).any():
            logger.error("Validation failed: REJECT found in description_value")
            return False

        if cleaned_desc.fillna("").str.slice(0, 15).str.contains("DISPUTED", na=False, case=False).any():
            logger.error("Validation failed: DISPUTED found in description_value")
            return False

        logger.info(f"Validation successful. Total number of Vulnerability Nodes: {df.shape[0]}")
        return True

    def prepare_output_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        rename_map = {
            "description_value": "description",
            "num_reference": "numOfReference",
        }
        output_df = df.rename(columns=rename_map).copy()
        output_df = output_df[self.CSV_COLUMNS]
        return output_df

    def save_processed_csv(self, df: pd.DataFrame) -> None:
        os.makedirs(os.path.dirname(self.combined_parsed_saved_df), exist_ok=True)
        output_df = self.prepare_output_dataframe(df)
        output_df.to_csv(self.combined_parsed_saved_df, index=False)
        logger.info(
            f"Saved processed CSV to {self.combined_parsed_saved_df} with shape {output_df.shape}"
        )

    def migrate_data(self) -> bool:
        if not self.neo4j_driver:
            logger.error("No Neo4j driver found. Please initialize the pipeline with a Neo4j driver.")
            return False

        try:
            logger.info(f"Reading CSV data from {self.combined_parsed_saved_df}")
            df = pd.read_csv(self.combined_parsed_saved_df, low_memory=False)

            if list(df.columns) != self.CSV_COLUMNS:
                logger.error(
                    f"Unexpected CSV schema. Expected {len(self.CSV_COLUMNS)} columns, got {len(df.columns)}"
                )
                logger.error(f"Actual columns: {list(df.columns)}")
                return False

            logger.info("Converting data types to match Neo4j expectations...")

            if "publishedDate" in df.columns:
                df["publishedDate"] = pd.to_datetime(df["publishedDate"], errors="coerce").dt.strftime("%Y-%m-%d")

            integer_fields = [
                "numOfReference",
                "v2impactScore",
                "v2exploitabilityScore",
                "v3impactScore",
                "v3exploitabilityScore",
            ]
            for field in integer_fields:
                if field in df.columns:
                    df[field] = pd.to_numeric(df[field], errors="coerce").fillna(0).astype(int)

            float_fields = [
                "v2version",
                "v2baseScore",
                "v3version",
                "v3baseScore",
            ]
            for field in float_fields:
                if field in df.columns:
                    df[field] = pd.to_numeric(df[field], errors="coerce").astype(float)

            boolean_fields = [
                "v2userInteractionRequired",
                "v2obtainUserPrivilege",
                "v2obtainAllPrivilege",
                "v2acInsufInfo",
                "v2obtainOtherPrivilege",
            ]
            for field in boolean_fields:
                if field in df.columns:
                    df[field] = df[field].apply(self._normalize_bool)

            text_fields = [
                "cveID",
                "description",
                "v2accessVector",
                "v2accessComplexity",
                "v2authentication",
                "v2confidentialityImpact",
                "v2integrityImpact",
                "v2availabilityImpact",
                "v2vectorString",
                "v2severity",
                "v3attackVector",
                "v3attackComplexity",
                "v3privilegesRequired",
                "v3userInteraction",
                "v3scope",
                "v3confidentialityImpact",
                "v3integrityImpact",
                "v3availabilityImpact",
                "v3vectorString",
                "v3baseSeverity",
            ]
            for field in text_fields:
                if field in df.columns:
                    df[field] = df[field].fillna("").astype(str).apply(self._clean_description)

            all_columns = list(df.columns)
            logger.info(f"Prepared DataFrame with {len(all_columns)} columns and {len(df)} rows")

            batch_size = 1000
            num_batches = (len(df) + batch_size - 1) // batch_size
            logger.info(f"Processing migration in {num_batches} batches...")

            with self.neo4j_driver.session() as session:
                try:
                    session.run(
                        "CREATE CONSTRAINT UniqueCveID IF NOT EXISTS "
                        "ON (v:Vulnerability) ASSERT v.cveID IS UNIQUE"
                    )
                    logger.info("Ensured Neo4j uniqueness constraint on Vulnerability.cveID")
                except Exception as e:
                    logger.warning(f"Constraint creation note: {e}")

                total_processed = 0
                for i in range(0, len(df), batch_size):
                    batch_end = min(i + batch_size, len(df))
                    batch_df = df.iloc[i:batch_end]

                    records = []
                    for _, row in batch_df.iterrows():
                        props = self._get_properties(row, all_columns)
                        if props is not None:
                            records.append(props)

                    if not records:
                        logger.warning(f"Batch {i // batch_size + 1} has no valid records; skipping.")
                        continue

                    logger.info(
                        f"Processing batch {i // batch_size + 1}/{num_batches} "
                        f"(rows {i + 1}-{batch_end}, valid={len(records)})..."
                    )

                    session.execute_write(self._merge_vulnerability_batch, records)
                    total_processed += len(records)

                logger.info(f"Migration complete. Total records processed: {total_processed}")

            return True

        except Exception as e:
            logger.exception(f"Error during migration: {e}")
            return False

    @staticmethod
    def _normalize_bool(value) -> bool:
        if pd.isna(value):
            return False
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            value = value.strip().lower()
            if value == "true":
                return True
            if value == "false":
                return False
        return bool(value)

    @staticmethod
    def _get_properties(row, all_columns: List[str]) -> Optional[dict]:
        properties = {}

        for col in all_columns:
            value = row[col]

            if pd.isna(value):
                if col == "cveID":
                    return None
                properties[col] = None
            else:
                if isinstance(value, pd.Timestamp):
                    properties[col] = value.strftime("%Y-%m-%d")
                else:
                    properties[col] = value

        if not properties.get("cveID"):
            return None

        return properties

    @staticmethod
    def _merge_vulnerability_batch(tx, records: List[dict]) -> None:
        query = """
        UNWIND $rows AS row
        MERGE (n:Vulnerability {cveID: row.cveID})
        SET n += row
        """
        tx.run(query, rows=records)

    @staticmethod
    def _parse_single_json_to_df(json_path: str) -> pd.DataFrame:
        """
        Parse a single NVD JSON 2.0 file into the legacy 35-column company schema.
        Missing fields remain None.
        """
        with open(json_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        vulnerabilities = data.get("vulnerabilities", [])
        rows = []

        for entry in vulnerabilities:
            cve = entry.get("cve", {})
            metrics = cve.get("metrics", {})

            cve_id = cve.get("id")
            published_date = cve.get("published")

            description_value = None
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description_value = desc.get("value")
                    break
            if description_value is None and cve.get("descriptions"):
                description_value = cve["descriptions"][0].get("value")

            num_ref = len(cve.get("references", []))

            # CVSS v2
            cvss_v2_list = metrics.get("cvssMetricV2", [])
            cvss_v2_entry = cvss_v2_list[0] if cvss_v2_list else {}
            cvss_v2 = cvss_v2_entry.get("cvssData", {})

            v2version = cvss_v2.get("version")
            v2baseScore = cvss_v2.get("baseScore")
            v2accessVector = cvss_v2.get("accessVector")
            v2accessComplexity = cvss_v2.get("accessComplexity")
            v2authentication = cvss_v2.get("authentication")
            v2confidentialityImpact = cvss_v2.get("confidentialityImpact")
            v2integrityImpact = cvss_v2.get("integrityImpact")
            v2availabilityImpact = cvss_v2.get("availabilityImpact")
            v2vectorString = cvss_v2.get("vectorString")

            v2impactScore = cvss_v2_entry.get("impactScore")
            v2exploitabilityScore = cvss_v2_entry.get("exploitabilityScore")
            v2userInteractionRequired = cvss_v2_entry.get("userInteractionRequired")
            v2severity = cvss_v2_entry.get("baseSeverity") or cvss_v2_entry.get("severity")
            v2obtainUserPrivilege = cvss_v2_entry.get("obtainUserPrivilege")
            v2obtainAllPrivilege = cvss_v2_entry.get("obtainAllPrivilege")
            v2acInsufInfo = cvss_v2_entry.get("acInsufInfo")
            v2obtainOtherPrivilege = cvss_v2_entry.get("obtainOtherPrivilege")

            # CVSS v3.1 preferred, fallback to v3.0
            cvss_v3_list = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
            cvss_v3_entry = cvss_v3_list[0] if cvss_v3_list else {}
            cvss_v3 = cvss_v3_entry.get("cvssData", {})

            v3version = cvss_v3.get("version")
            v3baseScore = cvss_v3.get("baseScore")
            v3attackVector = cvss_v3.get("attackVector")
            v3attackComplexity = cvss_v3.get("attackComplexity")
            v3privilegesRequired = cvss_v3.get("privilegesRequired")
            v3userInteraction = cvss_v3.get("userInteraction")
            v3scope = cvss_v3.get("scope")
            v3confidentialityImpact = cvss_v3.get("confidentialityImpact")
            v3integrityImpact = cvss_v3.get("integrityImpact")
            v3availabilityImpact = cvss_v3.get("availabilityImpact")
            v3vectorString = cvss_v3.get("vectorString")

            v3impactScore = cvss_v3_entry.get("impactScore")
            v3exploitabilityScore = cvss_v3_entry.get("exploitabilityScore")
            v3baseSeverity = cvss_v3.get("baseSeverity") or cvss_v3_entry.get("baseSeverity")

            rows.append({
                "cveID": cve_id,
                "publishedDate": published_date,
                "description_value": description_value,
                "num_reference": num_ref,
                "v2version": v2version,
                "v2baseScore": v2baseScore,
                "v2accessVector": v2accessVector,
                "v2accessComplexity": v2accessComplexity,
                "v2authentication": v2authentication,
                "v2confidentialityImpact": v2confidentialityImpact,
                "v2integrityImpact": v2integrityImpact,
                "v2availabilityImpact": v2availabilityImpact,
                "v2vectorString": v2vectorString,
                "v2impactScore": v2impactScore,
                "v2exploitabilityScore": v2exploitabilityScore,
                "v2userInteractionRequired": v2userInteractionRequired,
                "v2severity": v2severity,
                "v2obtainUserPrivilege": v2obtainUserPrivilege,
                "v2obtainAllPrivilege": v2obtainAllPrivilege,
                "v2acInsufInfo": v2acInsufInfo,
                "v2obtainOtherPrivilege": v2obtainOtherPrivilege,
                "v3version": v3version,
                "v3baseScore": v3baseScore,
                "v3attackVector": v3attackVector,
                "v3attackComplexity": v3attackComplexity,
                "v3privilegesRequired": v3privilegesRequired,
                "v3userInteraction": v3userInteraction,
                "v3scope": v3scope,
                "v3confidentialityImpact": v3confidentialityImpact,
                "v3integrityImpact": v3integrityImpact,
                "v3availabilityImpact": v3availabilityImpact,
                "v3vectorString": v3vectorString,
                "v3impactScore": v3impactScore,
                "v3exploitabilityScore": v3exploitabilityScore,
                "v3baseSeverity": v3baseSeverity,
            })

        df = pd.DataFrame(rows, columns=NVDPipeline.LEGACY_COLUMNS)

        if not df.empty and "publishedDate" in df.columns:
            df["publishedDate"] = pd.to_datetime(df["publishedDate"], errors="coerce").dt.date

        return df

    @staticmethod
    def _final_processing(df: pd.DataFrame) -> pd.DataFrame:
        logger.info("Starting final processing...")

        if "description_value" in df.columns:
            init_count = len(df)
            cleaned_desc = df["description_value"].fillna("").astype(str)

            mask_reject = cleaned_desc.str.slice(0, 15).str.contains("REJECT", na=False, case=False)
            mask_disputed = cleaned_desc.str.slice(0, 15).str.contains("DISPUTED", na=False, case=False)

            df = df[~mask_reject & ~mask_disputed].copy()

            removed = init_count - len(df)
            logger.info(f"Removed {removed} rows containing REJECT or DISPUTED. New shape: {df.shape}")
        else:
            logger.warning("No 'description_value' column found; skipping REJECT/DISPUTED filtering.")

        if "exploitTimeInDays" in df.columns:
            earliest_time = []
            earliest_index = []

            for val in df["exploitTimeInDays"]:
                if isinstance(val, float) and pd.isna(val):
                    earliest_time.append(None)
                    earliest_index.append(0)
                elif val == "[]":
                    earliest_time.append(None)
                    earliest_index.append(0)
                else:
                    numeric_list = list(map(int, re.sub(r"[\[\]'\,]", "", str(val)).split()))
                    if numeric_list:
                        min_val = min(numeric_list)
                        earliest_time.append(min_val)
                        earliest_index.append(numeric_list.index(min_val))
                    else:
                        earliest_time.append(None)
                        earliest_index.append(0)

            df["earliest_exploitTimeInDays"] = earliest_time
            df["earliest_index"] = earliest_index
            logger.info("Added earliest_exploitTimeInDays and earliest_index columns.")
        else:
            logger.info("No 'exploitTimeInDays' column found; skipping exploit time parsing.")

        if "description_value" in df.columns:
            df["description_value"] = df["description_value"].apply(NVDPipeline._clean_description)

        logger.info(f"Final processing complete. Final shape: {df.shape}")
        return df

    @staticmethod
    def _clean_description(text: str) -> str:
        if pd.isnull(text):
            return text
        text = re.sub(r"[\r\n]+", " ", str(text))
        text = text.replace('"', "'")
        text = re.sub(r"[\x00-\x1F\x7F]", "", text)
        return text.strip()

    def run(self) -> bool:
        try:
            logger.info("Starting NVD pipeline...")

            json_files = self.crawl_nvd_data()
            df = self.preprocess_files(json_files)

            if not self.validate_data(df):
                logger.error("Invalid data found in VulnerabilityNodes.csv")
                return False

            self.save_processed_csv(df)

            if not self.migrate_data():
                logger.error("Migration failed.")
                return False

            logger.info("Migration successful.")
            return True

        except Exception as e:
            logger.exception(f"Pipeline execution failed: {e}")
            return False


def main():
    driver = neo4j.GraphDatabase.driver(
        "bolt://localhost:7687",
        auth=("neo4j", "Vanly180705!")
    )
    assert_neo4j_connection(driver)

    nvd_pipeline = NVDPipeline(driver)
    success = nvd_pipeline.run()

    if success:
        logger.info("Pipeline execution successful.")
    else:
        logger.error("Pipeline execution failed.")


if __name__ == "__main__":
    main()