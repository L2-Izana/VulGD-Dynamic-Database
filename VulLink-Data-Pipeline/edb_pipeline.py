import os
from urllib.request import urlopen
from bs4 import BeautifulSoup
import neo4j
import pandas as pd
import json

class EDBPipeline:
    def __init__(self, neo4j_driver: neo4j.GraphDatabase.driver):
        self.neo4j_driver = neo4j_driver
        self.saved_df = "./datasource/ExploitNodes.csv"
        self.current_page_number = json.load(open("pipeline_config.json"))["edb_current_page"]

    def run(self):
        base_url = "https://www.exploit-db.com/exploits/"
        csv_header = ["eid", "exploitPublishDate", "author", "exploitType", "platform"]

        # Create directory from file path
        os.makedirs(os.path.dirname(self.saved_df), exist_ok=True)

        # Initialize csv_list with the header if file doesn't exist
        csv_list = []
        if not os.path.exists(self.saved_df):
            with open(self.saved_df, "w", encoding="utf-8") as f:
                f.write(",".join(csv_header) + "\n")
        
        rows_processed = 0
        batch_size = 1000
        
        while True:
            page_url = base_url + str(self.current_page_number)
            print(f"Crawling page {self.current_page_number}...")
            try:
                page = urlopen(page_url)
                content = page.read().decode("utf-8")
            except Exception as e:
                print(f"Error accessing page {self.current_page_number}: {e}")
                # Check if the previous page is the last page, meaning that no more exploits have been discovered yet
                previous_page = urlopen(base_url + str(self.current_page_number-1))
                previous_content = previous_page.read().decode("utf-8")
                soup = BeautifulSoup(previous_content, "html.parser")
                btn_group = soup.find('div', class_='btn-group float-right')
                exploit_href = btn_group.find('a').get('href')
                is_next_page_valid = exploit_href != '/exploits/#'
                if not is_next_page_valid: # If the previous page does not have a next page, then we have reached the end of the pages
                    print("Reached end of pages.")
                    break
                self.current_page_number += 1
                continue

            soup = BeautifulSoup(content, "html.parser")
            tags = soup.find_all('h6', class_='stats-title')
            # Verify that expected number of tags is present
            if len(tags) < 6:
                print("Not enough tags found on page, stopping crawl.")
                self.current_page_number += 1
                continue

            # Clean and sanitize the text values before adding to CSV
            try:
                edbid = "EXPLOIT-DB:" + self._clean_text(tags[0].get_text().strip())
                author = self._clean_text(tags[2].get_text().strip())
                exploit_type = self._clean_text(tags[3].get_text().strip())
                platform = self._clean_text(tags[4].get_text().strip())
                exploit_date = self._clean_text(tags[5].get_text().strip())
                
                csv_item = [edbid, exploit_date, author, exploit_type, platform]
                csv_list.append(csv_item)
                rows_processed += 1
            except Exception as e:
                print(f"Error processing page {self.current_page_number}: {e}")
                self.current_page_number += 1
                continue

            # Write to CSV in batches of 1000 rows
            if len(csv_list) >= batch_size:
                self._write_csv_batch(csv_list)
                csv_list = []

            # Look for the next page URL from the button group
            btn_group = soup.find('div', class_='btn-group float-right')
            if not btn_group:
                print("No pagination button found, ending crawl.")
                json.dump({"edb_current_page": self.current_page_number+1}, open("pipeline_config.json", "w"))
                break

            # This button is the next page button in the ExploitDB website
            exploit_href = btn_group.find('a').get('href')
            is_next_page_valid = exploit_href != '/exploits/#'
            if not is_next_page_valid:
                print("Reached end of pages.")
                json.dump({"edb_current_page": self.current_page_number+1}, open("pipeline_config.json", "w"))
                break

            self.current_page_number += 1

        # Write any remaining data to CSV
        if csv_list:
            self._write_csv_batch(csv_list)

        print(f"Data saved to {self.saved_df}. Total records processed: {rows_processed}")

    def _clean_text(self, text):
        """Clean and normalize text to prevent encoding issues"""
        if not text:
            return ""
        
        # Remove spaces
        text = text.replace(" ", "")
        
        # Remove control characters, keep only printable
        text = ''.join(c for c in text if c.isprintable())
        
        # Replace quotes with escaped quotes to avoid CSV issues
        text = text.replace('"', '""')
        
        return text

    def _write_csv_batch(self, csv_list):
        """Write a batch of data to CSV with proper encoding handling"""
        print(f"Writing batch of {len(csv_list)} rows to CSV...")
        with open(self.saved_df, "a", encoding="utf-8", errors="replace") as f:
            for item in csv_list:
                # Quote values that might contain commas or special characters
                quoted_items = [f'"{item}"' if ',' in item else item for item in item]
                f.write(",".join(quoted_items) + "\n")

    def migrate_data(self):
        """
        Migrates the EDB exploit data to Neo4j, handling potential encoding issues.
        Skips rows with unexpected column counts instead of failing.
        """
        if not self.neo4j_driver:
            print("No Neo4j driver found. Please initialize the pipeline with a Neo4j driver.")
            return False
        try:
            print(f"Reading CSV data from {self.saved_df}")
            
            # Use error_bad_lines=False (renamed to on_bad_lines in newer pandas)
            try:
                # For newer pandas versions
                df = pd.read_csv(self.saved_df, encoding='utf-8', on_bad_lines='skip', low_memory=False)
                print("Using pandas newer version with on_bad_lines='skip'")
            except TypeError:
                # For older pandas versions
                df = pd.read_csv(self.saved_df, encoding='utf-8', error_bad_lines=False, warn_bad_lines=True, low_memory=False)
                print("Using pandas older version with error_bad_lines=False")
            
            # Verify we have data
            if df.empty:
                print("No data could be read from the CSV file.")
                return False
            
            print(f"Successfully read {len(df)} rows from CSV with {df.shape[1]} columns")
            
            # Clean the data of potential problematic characters
            corrected_columns_names = ['eid', 'exploitPublishDate', 'author', 'exploitType', 'platform']
            
            # Ensure the DataFrame has the right number of columns
            if df.shape[1] != len(corrected_columns_names):
                print(f"Warning: CSV has {df.shape[1]} columns, expected {len(corrected_columns_names)}.")
                
                # If we have more columns than expected, drop the extras
                if df.shape[1] > len(corrected_columns_names):
                    df = df.iloc[:, :len(corrected_columns_names)]
                    print(f"Trimmed to {len(corrected_columns_names)} columns.")
                    
                # If we have fewer columns than expected, add empty ones
                while df.shape[1] < len(corrected_columns_names):
                    df[f'empty_{df.shape[1]}'] = ""
                    print(f"Added empty column {df.shape[1]}")
            
            # Now it's safe to rename columns
            df.columns = corrected_columns_names
            
            # Clean text columns to ensure they don't contain invalid characters
            text_columns = ['eid', 'author', 'exploitType', 'platform']
            for col in text_columns:
                if col in df.columns:
                    # Replace non-printable characters and normalize strings
                    df[col] = df[col].astype(str).apply(lambda x: ''.join(c for c in x if c.isprintable()))
            
            print("Converting data types to match Neo4j expectations...")
            
            # Convert date fields
            try:
                df['exploitPublishDate'] = pd.to_datetime(df['exploitPublishDate'], errors='coerce').dt.strftime('%Y-%m-%d')
                # Fill NaT values with a default date
                df['exploitPublishDate'] = df['exploitPublishDate'].fillna('2000-01-01')
            except Exception as e:
                print(f"Warning: Error converting exploitPublishDate: {e}")
                df['exploitPublishDate'] = '2000-01-01'  # Use default date if conversion fails

            batch_size = 1000
            total_rows = len(df)
            
            # Create or update nodes
            print("Migrating Exploit and Author nodes...")
            for i in range(0, total_rows, batch_size):
                end_idx = min(i + batch_size, total_rows)
                batch = df.iloc[i:end_idx]
                with self.neo4j_driver.session() as session:
                    for _, row in batch.iterrows():
                        try:
                            # Check if row has all required data
                            if pd.isna(row["eid"]) or not row["eid"]:
                                print(f"Skipping row with missing eid: {row.to_dict()}")
                                continue
                            
                            # Create Exploit node
                            session.run(
                                "MERGE (e:Exploit {eid: $eid}) "
                                "SET e.exploitPublishDate = date($exploitPublishDate), "
                                "    e.exploitType = $exploitType, "
                                "    e.platform = $platform",
                                {
                                    "eid": row["eid"],
                                    "exploitPublishDate": row["exploitPublishDate"],
                                    "exploitType": row["exploitType"],
                                    "platform": row["platform"]
                                }
                            )
                            
                            # Check if author field is valid
                            if not pd.isna(row["author"]) and row["author"]:
                                # Create Author node
                                session.run(
                                    "MERGE (a:Author {authorName: $author}) "
                                    "SET a.authorName = $author",
                                    {"author": row["author"]}
                                )
                        except Exception as e:
                            print(f"Error processing row: {row.to_dict()}, Error: {e}")
                
                print(f"Processed {end_idx}/{total_rows} rows for Exploit and Author nodes")
            
            # Create relationships between authors and exploits
            print("Creating WRITES relationships...")
            for i in range(0, total_rows, batch_size):
                end_idx = min(i + batch_size, total_rows)
                batch = df.iloc[i:end_idx]
                with self.neo4j_driver.session() as session:
                    for _, row in batch.iterrows():
                        try:
                            # Skip if either eid or author is missing
                            if pd.isna(row["eid"]) or pd.isna(row["author"]) or not row["eid"] or not row["author"]:
                                continue
                            
                            session.run(
                                "MATCH (e:Exploit {eid: $eid}) "
                                "MATCH (a:Author {authorName: $author}) "
                                "MERGE (a)-[:WRITES]->(e)",
                                {"eid": row["eid"], "author": row["author"]}
                            )
                        except Exception as e:
                            print(f"Error creating relationship for: {row['eid']} - {row['author']}, Error: {e}")
                
                print(f"Processed {end_idx}/{total_rows} rows for WRITES relationships")
            
            print("Migration completed successfully")
            return True
        except Exception as e:
            print(f"Error during migration: {e}")
            import traceback
            traceback.print_exc()  # Print the full traceback for debugging
            return False

if __name__ == "__main__":
    # Initialize the Neo4j driver
    driver = neo4j.GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Vanly180705!"))
    # Pass the driver to the pipeline
    edb_pipeline = EDBPipeline(neo4j_driver=driver)

    # Run the web crawling and CSV saving process
    edb_pipeline.run()

    # Uncomment below to run the data migration after crawling
    if edb_pipeline.migrate_data():
        print("Data migrated successfully!")
    else:
        print("Data migration failed.")
