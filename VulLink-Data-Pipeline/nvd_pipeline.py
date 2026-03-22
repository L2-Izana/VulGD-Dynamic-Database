import json
import os
import zipfile
import neo4j
import tempfile
import subprocess
import platform
import pandas as pd
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
import wget
import re

def debug_checks(chrome_options, user_data_dir, driver_path):
    """Debug function for Linux environments"""
    print("\n=== Debugging Information ===")
    print("Chrome Options Arguments:", chrome_options.arguments)
    print("Temporary User Data Directory:", user_data_dir)
    if os.path.exists(user_data_dir):
        print(f"User Data Directory exists at: {user_data_dir}")
    else:
        print(f"User Data Directory does NOT exist: {user_data_dir}")
    print("ChromeDriver path:", driver_path)
    print("\nExisting Chrome Processes:")
    try:
        # List running processes with 'chrome' in the name
        if platform.system() == "Linux":
            result = subprocess.run(["pgrep", "-a", "chrome"], capture_output=True, text=True)
            if result.stdout.strip():
                print(result.stdout)
            else:
                print("No existing Chrome processes found.")
        else:
            print("Process checking skipped on non-Linux platform")
    except Exception as e:
        print("Error checking Chrome processes:", e)
    print("=== End Debug Info ===\n")

class NVDPipeline:
    def __init__(self, neo4j_driver: neo4j.GraphDatabase.driver):
        self.neo4j_driver = neo4j_driver
        self.output_dir = "./datasource/NVD"
        self.combined_parsed_saved_df = "./datasource/VulnerabilityNodes.csv"
        
        # Set platform-specific settings
        self.is_linux = platform.system() == "Linux"
        if self.is_linux:
            # Linux-specific settings
            self.driver_path = "/usr/local/bin/chromedriver"
        else:
            # Windows/MacOS settings
            self.driver_path = None  # Will use ChromeDriverManager
    
    def crawl_nvd_data(self)->list[str]:
        url = "https://nvd.nist.gov/vuln/data-feeds"
        json_files:list[str] = []
        print(f"Initializing WebDriver for platform: {platform.system()}...")
        
        chrome_options = Options()
        chrome_options.add_argument("--start-maximized")
        chrome_options.add_argument("--headless")  # Run Chrome in headless mode
        
        # Platform-specific configurations
        user_data_dir = None
        if self.is_linux:
            # Linux-specific options
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            
            # Create a temporary directory for user data
            user_data_dir = tempfile.mkdtemp()
            chrome_options.add_argument(f"--user-data-dir={user_data_dir}")
            
            # Debug checks on Linux
            debug_checks(chrome_options, user_data_dir, self.driver_path)
            
            # Initialize with specific driver path on Linux
            service = Service(self.driver_path)
        else:
            # Windows/Mac: Use ChromeDriverManager
            from webdriver_manager.chrome import ChromeDriverManager
            service = Service(ChromeDriverManager().install())

        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)

        with webdriver.Chrome(service=service, options=chrome_options) as driver:
            print(f"Navigating to {url}...")
            driver.get(url)

            # Wait for ZIP links
            print("Waiting for ZIP links to appear...")
            links = WebDriverWait(driver, 20).until(
                EC.presence_of_all_elements_located((By.PARTIAL_LINK_TEXT, 'ZIP'))
            )

            # Filter links: must include 'nvdcve-1.1-', 'json', and end with '.zip'
            json_zip_links = []
            for link in links:
                href = link.get_attribute('href')
                if href:
                    href_lower = href.lower()
                    if ("nvdcve-1.1-" in href_lower
                        and "json" in href_lower
                        and href_lower.endswith(".zip")):
                        json_zip_links.append(href)

            print("\nFiltered ZIP links to download:")
            for link_url in json_zip_links:
                print(f"  {link_url}")

            # Download & unzip each link
            for link_url in json_zip_links:
                print(f"\nDownloading: {link_url}")
                downloaded_zip_path = wget.download(link_url, out=self.output_dir)
                print(f"\nDownloaded file: {downloaded_zip_path}")

                # Unzip the file if it ends with .zip
                if downloaded_zip_path.lower().endswith(".zip"):
                    with zipfile.ZipFile(downloaded_zip_path, 'r') as zip_ref:
                        zip_ref.extractall(self.output_dir)
                    os.remove(downloaded_zip_path)
                    print(f"Unzipped and removed: {downloaded_zip_path}")

        # Gather all .json files
        for fname in os.listdir(self.output_dir):
            if fname.lower().endswith(".json"):
                full_path = os.path.join(self.output_dir, fname)
                json_files.append(full_path)

        print("\nAll JSON files:")
        for f in json_files:
            print(f)
            
        return json_files
    
    def preprocess_files(self, json_files: list[str])->pd.DataFrame:
        """
        1) Parses each .json file in json_files into a DataFrame.
        2) Concatenates them into combined_df.
        3) Deduplicates data.
        4) Calls final_processing() to further clean/filter data.
        5) Optionally saves each individual DataFrame as .pkl.
        The final result is stored in combined_df.
        """
        if not json_files:
            print("No JSON files to process. Did you call download_data first?")
            return

        print("\nParsing JSON files...")
        parsed_dataframes: list[pd.DataFrame] = []

        for json_path in json_files:
            df: pd.DataFrame = NVDPipeline._parse_single_json_to_df(json_path)
            parsed_dataframes.append(df)

        # Combine all DataFrames
        if parsed_dataframes:
            combined_df: pd.DataFrame = pd.concat(parsed_dataframes, ignore_index=True)
            print(f"\nCombined {len(parsed_dataframes)} DataFrames. "
                  f"Shape before deduplication: {combined_df.shape}.")

            # Deduplicate (by all columns; adjust subset if needed)
            before_count = len(combined_df)
            combined_df.drop_duplicates(inplace=True)
            after_count = len(combined_df)
            print(f"Removed {before_count - after_count} duplicate rows. "
                  f"Final row count: {after_count}")

            # Perform additional final processing
            combined_df = NVDPipeline._final_processing(combined_df)
        else:
            print("No DataFrames were created. Nothing to combine.")

        return combined_df
    
    def validate_data(self, df: pd.DataFrame)->bool:
        """
        Validates the data of the VulnerabilityNodes.csv file.
        Ensure that every row has 35 properties.
        Ensure that the description_value is not malformed.
        Ensure that the description_value does not contain REJECT or DISPUTED.
        Count the total number of Vulnerability Nodes.
        """
        if df.shape[1] != 35:
            print(f"Invalid number of columns: {df.shape[1]}")
            return False
        if df['description_value'].apply(NVDPipeline._clean_description).isnull().any():
            print("Malformed description_value found")
            return False
        if df['description_value'].str.slice(0, 15).str.contains('REJECT', na=False, case=False).any():
            print("REJECT found in description_value")
            return False
        if df['description_value'].str.slice(0, 15).str.contains('DISPUTED', na=False, case=False).any():
            print("DISPUTED found in description_value")
            return False
        print(f"Total number of Vulnerability Nodes: {df.shape[0]}")
        return True
    
    def migrate_data(self):
        """
        Migrates the data to the Neo4j database by:
        1. Reading the CSV file with all 35 columns.
        2. Correcting the column names.
        3. Converting data types to match Neo4j expectations.
        4. Getting all column names.
        5. Creating a batch of 1000 rows to migrate.
        
        Returns:
            bool: True if migration was successful, False otherwise
        """
        if not self.neo4j_driver:
            print("No Neo4j driver found. Please initialize the pipeline with a Neo4j driver.")
            return False
        try:
            # Read the CSV file with all 35 columns
            print(f"Reading CSV data from {self.combined_parsed_saved_df}")
            df = pd.read_csv(self.combined_parsed_saved_df, low_memory=False)
                        
            # Correct the column names
            corrected_columns_names = ['cveID', 'publishedDate', 'description', 'numOfReference', 'v2version', 'v2baseScore', 'v2accessVector', 'v2accessComplexity', 'v2authentication', 'v2confidentialityImpact', 'v2integrityImpact', 'v2availabilityImpact', 'v2vectorString', 'v2impactScore', 'v2exploitabilityScore', 'v2userInteractionRequired', 'v2severity', 'v2obtainUserPrivilege', 'v2obtainAllPrivilege', 'v2acInsufInfo', 'v2obtainOtherPrivilege', 'v3version', 'v3baseScore', 'v3attackVector', 'v3attackComplexity', 'v3privilegesRequired', 'v3userInteraction', 'v3scope', 'v3confidentialityImpact', 'v3integrityImpact', 'v3availabilityImpact', 'v3vectorString', 'v3impactScore', 'v3exploitabilityScore', 'v3baseSeverity']
            df.columns = corrected_columns_names
            
            print("Converting data types to match Neo4j expectations...")
            
            # Convert date fields
            try:
                df['publishedDate'] = pd.to_datetime(df['publishedDate'], errors='coerce').dt.strftime('%Y-%m-%d')
            except Exception as e:
                print(f"Warning: Error converting publishedDate: {e}")
                
            # Convert integer fields
            integer_fields = ['numOfReference', 'v2version', 'v2impactScore', 'v2exploitabilityScore', 'v3baseScore', 'v3impactScore', 'v3exploitabilityScore']
            
            for field in integer_fields:
                try:
                    df[field] = pd.to_numeric(df[field], errors='coerce').fillna(0).astype(int)
                except Exception as e:
                    print(f"Warning: Error converting {field} to integer: {e}")
                    
            # Convert float fields  
            float_fields = ['v2baseScore', 'v3version']
            
            for field in float_fields:
                try:
                    df[field] = pd.to_numeric(df[field], errors='coerce').fillna(0.0).astype(float)
                except Exception as e:
                    print(f"Warning: Error converting {field} to float: {e}")
                    
            # Convert boolean fields
            boolean_fields = ['v2userInteractionRequired', 'v2obtainUserPrivilege', 'v2obtainAllPrivilege', 'v2acInsufInfo', 'v2obtainOtherPrivilege']
            
            for field in boolean_fields:
                try:
                    df[field] = df[field].apply(lambda x: 
                        True if isinstance(x, str) and x.lower() == 'true' 
                        else False if isinstance(x, str) and x.lower() == 'false'
                        else bool(x) if pd.notna(x) 
                        else False
                    )
                except Exception as e:
                    print(f"Warning: Error converting {field} to boolean: {e}")
            
            # Clean text fields to prevent issues with quotes, newlines, etc.
            text_fields = ['description', 'v2accessVector', 'v2accessComplexity', 'v2authentication', 'v2confidentialityImpact', 'v2integrityImpact', 'v2availabilityImpact', 'v2vectorString', 'v2severity', 'v3attackVector', 'v3attackComplexity', 'v3privilegesRequired', 'v3userInteraction', 'v3scope', 'v3confidentialityImpact', 'v3integrityImpact', 'v3availabilityImpact', 'v3vectorString', 'v3baseSeverity']
            
            for field in text_fields:
                if field in df.columns:
                    df[field] = df[field].astype(str)
                    df[field] = df[field].apply(lambda x: x.replace('\r', ' ').replace('\n', ' '))

            # Get all column names (should be 35).
            all_columns = list(df.columns)
            print(f"Prepared DataFrame with {len(all_columns)} columns and {len(df)} rows")
            
            # Process in batches
            batch_size = 1000
            num_batches = (len(df) + batch_size - 1) // batch_size  # Ceiling division
            print(f"Processing migration in {num_batches} batches...")
            
            with self.neo4j_driver.session() as session:
                # Create constraint if it doesn't exist already
                try:
                    session.run("CREATE CONSTRAINT UniqueCveID IF NOT EXISTS ON (v:Vulnerability) ASSERT v.cveID IS UNIQUE")
                except Exception as e:
                    print(f"Note: Constraint creation message: {e}")
                    
                # Process batches with the type-converted DataFrame
                total_processed = 0
                for i in range(0, len(df), batch_size):
                    batch_end = min(i + batch_size, len(df))
                    batch_df = df.iloc[i:batch_end]
                    print(f"Processing batch {i//batch_size + 1}/{num_batches} (rows {i+1}-{batch_end})...")
                    try:
                        NVDPipeline._process_batch(batch_df, session, batch_size, all_columns)
                        total_processed += len(batch_df)
                    except Exception as e:
                        print(f"Error in batch {i//batch_size + 1}: {e}")
                    
                print(f"Migration complete. Total records processed: {total_processed}")
            return True
        except Exception as e:
            print(f"Error during migration: {e}")
            return False

    @staticmethod
    def _get_properties(row, all_columns: list[str])->dict:
        """
        For each row, convert it to a dictionary with proper typing for Neo4j.
        The types have already been converted in the DataFrame.
        
        Args:
            row: A pandas Series representing a row in the DataFrame
            all_columns: List of column names
            
        Returns:
            dict: A dictionary of properties for Neo4j
        """
        properties = {}
        
        for col in all_columns:
            if pd.isna(row[col]):
                # Handle NULL values appropriately for different types
                if col == 'cveID':  # Skip rows with no CVE ID
                    return None
                elif col in ['v2baseScore', 'v3version']:  # Float fields
                    properties[col] = 0.0
                elif col in ['numOfReference', 'v2version', 'v2impactScore', 'v2exploitabilityScore', 
                             'v3baseScore', 'v3impactScore', 'v3exploitabilityScore']:  # Integer fields
                    properties[col] = 0
                elif col in ['v2userInteractionRequired', 'v2obtainUserPrivilege', 
                             'v2obtainAllPrivilege', 'v2acInsufInfo', 'v2obtainOtherPrivilege']:  # Boolean fields
                    properties[col] = False
                else:  # String fields
                    properties[col] = "None"
            else:
                # The type conversion already happened at the DataFrame level
                properties[col] = row[col]
        
        return properties

    @staticmethod
    def _merge_vulnerability_node(tx, properties):
        """
        Merge (or create) a Vulnerability node using the unique 'cveID' key.
        Updates the node with all properties.
        """
        if not properties or 'cveID' not in properties or not properties['cveID'] or properties['cveID'] == "None":
            return  # Skip invalid records
        
        query = """
        MERGE (n:Vulnerability {cveID: $cveID})
        SET n += $props
        """
        tx.run(query, cveID=properties.get("cveID"), props=properties)

    @staticmethod
    def _process_batch(df: pd.DataFrame, session, batch_size: int, all_columns: list[str]):
        """
        Process the DataFrame in batches.
        """
        processed = 0
        skipped = 0
        
        for index, row in df.iterrows():
            properties = NVDPipeline._get_properties(row, all_columns)
            if properties is None:
                skipped += 1
                continue
            
            try:
                session.execute_write(NVDPipeline._merge_vulnerability_node, properties)
                processed += 1
            except Exception as e:
                print(f"Error processing row {index} (cveID={row.get('cveID', 'unknown')}): {e}")
        
        print(f"Batch complete: {processed} records processed, {skipped} records skipped")

    @staticmethod
    def _parse_single_json_to_df(json_path: str)->pd.DataFrame:
        """
        Parses a single JSON file from NVD into a DataFrame.
        """
        with open(json_path, 'r', errors='ignore') as f:
            data = json.load(f)

        cve_items = data.get('CVE_Items', [])
        rows = []

        for item in cve_items:
            cve = item.get('cve', {})
            meta = cve.get('CVE_data_meta', {})
            impact = item.get('impact', {})

            cve_id = meta.get('ID')
            published_date = item.get('publishedDate')
            description_data = cve.get('description', {}).get('description_data', [])
            description_value = description_data[0].get('value') if description_data else None
            num_ref = len(cve.get('references', {}).get('reference_data', []))

            base_metric_v2 = impact.get('baseMetricV2', {})
            cvss_v2 = base_metric_v2.get('cvssV2', {})

            v2version                  = cvss_v2.get('version')
            v2baseScore                = cvss_v2.get('baseScore')
            v2accessVector             = cvss_v2.get('accessVector')
            v2accessComplexity         = cvss_v2.get('accessComplexity')
            v2authentication           = cvss_v2.get('authentication')
            v2confidentialityImpact    = cvss_v2.get('confidentialityImpact')
            v2integrityImpact          = cvss_v2.get('integrityImpact')
            v2availabilityImpact       = cvss_v2.get('availabilityImpact')
            v2vectorString             = cvss_v2.get('vectorString')

            v2impactScore              = base_metric_v2.get('impactScore')
            v2exploitabilityScore      = base_metric_v2.get('exploitabilityScore')
            v2userInteractionRequired  = base_metric_v2.get('userInteractionRequired')
            v2severity                 = base_metric_v2.get('severity')
            v2obtainUserPrivilege      = cvss_v2.get('obtainUserPrivilege')
            v2obtainAllPrivilege       = cvss_v2.get('obtainAllPrivilege')
            v2acInsufInfo              = cvss_v2.get('acInsufInfo')
            v2obtainOtherPrivilege     = cvss_v2.get('obtainOtherPrivilege')

            base_metric_v3 = impact.get('baseMetricV3', {})
            cvss_v3 = base_metric_v3.get('cvssV3', {})

            v3version                  = cvss_v3.get('version')
            v3baseScore                = cvss_v3.get('baseScore')
            v3attackVector             = cvss_v3.get('attackVector')
            v3attackComplexity         = cvss_v3.get('attackComplexity')
            v3privilegesRequired       = cvss_v3.get('privilegesRequired')
            v3userInteraction          = cvss_v3.get('userInteraction')
            v3scope                    = cvss_v3.get('scope')
            v3confidentialityImpact    = cvss_v3.get('confidentialityImpact')
            v3integrityImpact          = cvss_v3.get('integrityImpact')
            v3availabilityImpact       = cvss_v3.get('availabilityImpact')
            v3vectorString             = cvss_v3.get('vectorString')

            v3impactScore              = base_metric_v3.get('impactScore')
            v3exploitabilityScore      = base_metric_v3.get('exploitabilityScore')
            v3baseSeverity             = cvss_v3.get('baseSeverity')

            rows.append({
                'cveID': cve_id,
                'publishedDate': published_date,
                'description_value': description_value,
                'num_reference': num_ref,
                'v2version': v2version,
                'v2baseScore': v2baseScore,
                'v2accessVector': v2accessVector,
                'v2accessComplexity': v2accessComplexity,
                'v2authentication': v2authentication,
                'v2confidentialityImpact': v2confidentialityImpact,
                'v2integrityImpact': v2integrityImpact,
                'v2availabilityImpact': v2availabilityImpact,
                'v2vectorString': v2vectorString,
                'v2impactScore': v2impactScore,
                'v2exploitabilityScore': v2exploitabilityScore,
                'v2userInteractionRequired': v2userInteractionRequired,
                'v2severity': v2severity,
                'v2obtainUserPrivilege': v2obtainUserPrivilege,
                'v2obtainAllPrivilege': v2obtainAllPrivilege,
                'v2acInsufInfo': v2acInsufInfo,
                'v2obtainOtherPrivilege': v2obtainOtherPrivilege,
                'v3version': v3version,
                'v3baseScore': v3baseScore,
                'v3attackVector': v3attackVector,
                'v3attackComplexity': v3attackComplexity,
                'v3privilegesRequired': v3privilegesRequired,
                'v3userInteraction': v3userInteraction,
                'v3scope': v3scope,
                'v3confidentialityImpact': v3confidentialityImpact,
                'v3integrityImpact': v3integrityImpact,
                'v3availabilityImpact': v3availabilityImpact,
                'v3vectorString': v3vectorString,
                'v3impactScore': v3impactScore,
                'v3exploitabilityScore': v3exploitabilityScore,
                'v3baseSeverity': v3baseSeverity,
            })

        df = pd.DataFrame(rows)

        # Convert publishedDate to datetime.date if present
        if 'publishedDate' in df.columns and not df['publishedDate'].empty:
            df['publishedDate'] = pd.to_datetime(df['publishedDate'], format='%Y-%m-%dT%H:%MZ', errors='coerce')
            df['publishedDate'] = df['publishedDate'].dt.date

        return df

    @staticmethod
    def _final_processing(df: pd.DataFrame)->pd.DataFrame:
        """
        Performs final data cleaning/engineering on df:
         - Removes rows with REJECT or DISPUTED in description_value.
         - Parses earliest exploit time (if exploitTimeInDays exists).
         - Filter malformed description_value.
        """
        print("\nStarting final processing...")

        # 1. Remove REJECT and DISPUTED entries from 'description_value'
        if 'description_value' in df.columns:
            init_count = len(df)
            mask_reject = df['description_value'].str.slice(0, 15).str.contains('REJECT', na=False, case=False)
            df = df[~mask_reject]
            mask_disputed = df['description_value'].str.slice(0, 15).str.contains('DISPUTED', na=False, case=False)
            df = df[~mask_disputed]
            removed = init_count - len(df)
            print(f"Removed {removed} rows containing REJECT or DISPUTED. New shape: {df.shape}.")
        else:
            print("No 'description_value' column found; skipping REJECT/DISPUTED filtering.")

        # 2. Parses earliest exploit time (if exploitTimeInDays exists)
        if 'exploitTimeInDays' in df.columns:
            earliest_time = []
            earliest_index = []
            for val in df["exploitTimeInDays"]:
                if isinstance(val, float) and pd.isna(val):
                    earliest_time.append(None)
                    earliest_index.append(0)
                elif val == '[]':
                    earliest_time.append(None)
                    earliest_index.append(0)
                else:
                    numeric_list = list(map(int, re.sub(r'[\[\]\'\,]', '', val).split()))
                    if numeric_list:
                        min_val = min(numeric_list)
                        earliest_time.append(min_val)
                        earliest_index.append(numeric_list.index(min_val))
                    else:
                        earliest_time.append(None)
                        earliest_index.append(0)
            df["earliest_exploitTimeInDays"] = earliest_time
            df["earliest_index"] = earliest_index
            print("Added earliest_exploitTimeInDays & earliest_index columns.")
        else:
            print("No 'exploitTimeInDays' column found; skipping exploit time parsing.")
        
        df['description_value'] = df['description_value'].apply(NVDPipeline._clean_description)
        print("Final processing complete. Final shape:", df.shape)
        return df
    
    @staticmethod
    def _clean_description(text: str)->str: 
        # Fix malformed, note this in paper
        if pd.isnull(text):
            return text
        # Replace newline and carriage returns with a space
        text = re.sub(r'[\r\n]+', ' ', text)
        # Replace double quotes with single quotes (or remove them)
        text = text.replace('"', "'")
        # Remove any non-printable/control characters (ASCII 0-31 and 127)
        text = re.sub(r'[\x00-\x1F\x7F]', '', text)
        return text.strip()
    
    def run(self)->bool:
        """Main pipeline execution method"""
        try:
            # Execute the crawling step
            json_files:list[str] = self.crawl_nvd_data()
            
            # Additional processing steps
            df:pd.DataFrame = self.preprocess_files(json_files)
            if not self.validate_data(df):
                print("Invalid data found in VulnerabilityNodes.csv")
                return False
            else:
                print("Data validation successful.")

            # Save the processed data to a CSV file
            os.makedirs(os.path.dirname(self.combined_parsed_saved_df), exist_ok=True)
            df.to_csv(self.combined_parsed_saved_df, index=False)
            
            if not self.migrate_data():
                print("Migration failed.")
                return False
            else:
                print("Migration successful.")
            return True
        except Exception as e:
            print(f"Pipeline execution failed: {e}")
            return False

def main():
    # Initialize the pipeline with optional Neo4j driver
    driver = neo4j.GraphDatabase.driver(
        "bolt://localhost:7687",
        auth=("neo4j", "Vanly180705!")
    )

    nvd_pipeline = NVDPipeline(driver)
    
    # Run the complete pipeline
    success = nvd_pipeline.run()
    
    if success:
        print("Pipeline execution successful.")
    else:
        print("Pipeline execution failed.")

if __name__ == "__main__":
    main()
