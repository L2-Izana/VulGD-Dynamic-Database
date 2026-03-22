import csv
import shutil
import zipfile
import neo4j
from urllib.request import urlopen
import os
from tqdm import tqdm
import xml.etree.ElementTree as ET

class CWEPipeline:
    def __init__(self, neo4j_driver: neo4j.GraphDatabase.driver):
        self.neo4j_driver = neo4j_driver
        self.download_dir = "./datasource/CWE/cwec_latest.xml.zip"
        self.saved_df = "./datasource/WeaknessNodes.csv"

    def run(self):
        # Create datasource directory if it doesn't exist
        os.makedirs(os.path.dirname(self.download_dir), exist_ok=True)
        # Make sure the output directory exists
        os.makedirs(os.path.dirname(self.saved_df), exist_ok=True)
        
        url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
        print(f"Downloading CWE dataset from {url}...")
        
        try:
            # Download with progress tracking
            response = urlopen(url)
            total_size = int(response.info().get('Content-Length', 0))
            progress_bar = tqdm(total=total_size, unit='B', unit_scale=True, desc="Downloading")
            
            with open(self.download_dir, 'wb') as f:
                block_size = 8192  # 8KB chunks
                while True:
                    buffer = response.read(block_size)
                    if not buffer:
                        break
                    f.write(buffer)
                    progress_bar.update(len(buffer))
            progress_bar.close()
            print(f"Download completed. File saved to {self.download_dir}")
            
            # Extract the ZIP file
            extraction_path = "./datasource/CWE"
            os.makedirs(extraction_path, exist_ok=True)
            
            with zipfile.ZipFile(self.download_dir, 'r') as zip_ref:
                zip_ref.extractall(extraction_path)
            print("Extraction completed successfully.")
            
            # Locate the XML file in the extraction directory
            xml_files = [f for f in os.listdir(extraction_path) if f.endswith('.xml')]
            if not xml_files:
                raise FileNotFoundError("No XML files found in the extracted directory")
            
            xml_filename = xml_files[0]
            xml_path = os.path.join(extraction_path, xml_filename)
            print(f"Using XML file: {xml_path}")
            
            # Parse the XML file with ElementTree
            tree = ET.parse(xml_path)
            root = tree.getroot()
            # Use the correct namespace for CWE version 7
            namespaces = {'ns': 'http://cwe.mitre.org/cwe-7'}
            
            # Find all Weakness elements using the namespace
            weaknesses = root.findall(".//ns:Weakness", namespaces)
            print(f"Found {len(weaknesses)} Weakness elements")
            
            # Prepare the CSV header and list (without the view column)
            weakness_list = [["cweID", "cweName", "weaknessAbstraction", "status", "description", "extendedDescription"]]
            
            for weakness in weaknesses:
                cwe_id = weakness.get("ID", "").strip()
                cwe_name = weakness.get("Name", "").strip()
                abstraction = weakness.get("Abstraction", "").strip()
                status = weakness.get("Status", "").strip()
                
                # Extract the Description element
                desc_elem = weakness.find("ns:Description", namespaces)
                description = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ""
                
                # Extract the Extended_Description element, including inner text from child elements
                ext_desc_elem = weakness.find("ns:Extended_Description", namespaces)
                extended_description = ""
                if ext_desc_elem is not None:
                    if ext_desc_elem.text:
                        extended_description += ext_desc_elem.text.strip()
                    for child in ext_desc_elem:
                        if child.text:
                            extended_description += " " + child.text.strip()
                
                # Append the row data without the view column
                weakness_list.append([
                    cwe_id,
                    cwe_name,
                    abstraction,
                    status,
                    description,
                    extended_description
                ])
            
            # Write the collected data to CSV
            print(f"Writing {len(weakness_list)-1} weaknesses to CSV: {self.saved_df}")
            with open(self.saved_df, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerows(weakness_list)
                
            print("CWE processing completed successfully.")

            # Delete the CWE directory after processing
            cwe_directory = os.path.join(os.getcwd(), 'datasource', 'CWE')

            # Check if the directory exists
            if os.path.exists(cwe_directory):
                # Remove the directory and all its contents
                shutil.rmtree(cwe_directory)
                print(f"Deleted the directory: {cwe_directory}")
            else:
                print(f"The directory does not exist: {cwe_directory}")
            return True
            
        except Exception as e:
            print(f"Error downloading or processing CWE data: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def migrate_data(self):
        """
        Migrates the CWE weakness data from CSV to Neo4j database.
        Creates/updates Weakness nodes with all properties from the CSV file.
        """
        if not self.neo4j_driver:
            print("No Neo4j driver found. Please initialize the pipeline with a Neo4j driver.")
            return False
        
        try:
            print(f"Reading CWE data from {self.saved_df}")
            
            # Read CSV file
            with open(self.saved_df, 'r', encoding='utf-8') as csv_file:
                reader = csv.reader(csv_file)
                header = next(reader)  # Skip header row
                
                # Process in batches
                batch_size = 100
                current_batch = []
                total_processed = 0
                
                for row in reader:
                    if len(row) < 6:  # Ensure row has all expected columns
                        print(f"Skipping incomplete row: {row}")
                        continue
                    
                    cwe_id = row[0]
                    cwe_name = row[1]
                    weakness_abstraction = row[2]
                    status = row[3]
                    description = row[4]
                    extended_description = row[5]

                    # Add to current batch
                    current_batch.append({
                        'cweID': cwe_id,
                        'cweName': cwe_name,
                        'weaknessAbstraction': weakness_abstraction,
                        'status': status,
                        'description': description,
                        'extendedDescription': extended_description
                    })
                    
                    # Process batch when it reaches batch_size
                    if len(current_batch) >= batch_size:
                        self._process_weakness_batch(current_batch)
                        total_processed += len(current_batch)
                        print(f"Processed {total_processed} weaknesses")
                        current_batch = []
                
                # Process any remaining items
                if current_batch:
                    self._process_weakness_batch(current_batch)
                    total_processed += len(current_batch)
                
                print(f"Migration complete: {total_processed} CWE weaknesses imported into Neo4j")
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
                    # Create or update Weakness node
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
    
if __name__ == "__main__":
    driver = neo4j.GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Vanly180705!"))
    cwe_pipeline = CWEPipeline(driver)
    cwe_pipeline.run()
    cwe_pipeline.migrate_data()
