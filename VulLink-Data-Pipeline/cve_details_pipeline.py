import os
import traceback
from typing import Tuple
import neo4j
import csv
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import pandas as pd
import numpy as np
import random
import requests
import re
import time

class CVEDetailsPipeline:
    def __init__(self, neo4j_driver: neo4j.GraphDatabase.driver):
        self.neo4j_driver = neo4j_driver
        self.vul_weakness_file = "./datasource/VulnerabilityNodesAddProperties.csv"
        self.vul_weakness_header = ["cveID", "cweID", "vulnerabilityType"]
        self.vul_domain_file = "./datasource/DomainNodes_Vulnerability_HAS_REFERENCE_Domain_relationship.csv"
        self.vul_domain_header = ["cveID", "domainName"]
        self.vul_product_file = "./datasource/ProductNodes_Vulnerability_HAS_REFERENCE_Product_relationship.csv"
        self.vul_product_header = ["cveID", "productType", "vendorName", "productName", "numOfVersion"] 
        self.affect_property_file = "./datasource/AffectsAddProperty.csv"
        self.affect_property_header = ["cveID", "productName", "version"]
        self.user_agents = [
            'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.7) Gecko/2009021910 Firefox/3.0.7',
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:30.0) Gecko/20100101 Firefox/30.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/537.75.14",
            "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Win64; x64; Trident/6.0)",
            'Mozilla/5.0 (Windows; U; Windows NT 5.1; it; rv:1.8.1.11) Gecko/20071127 Firefox/2.0.0.11',
            'Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.5 (like Gecko) (Kubuntu)',
            'Lynx/2.8.5rel.1 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/1.2.9',
            "Mozilla/5.0 (X11; Linux i686) AppleWebKit/535.7 (KHTML, like Gecko) Ubuntu/11.04 Chromium/16.0.912.77 Chrome/16.0.912.77 Safari/535.7",
            "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:10.0) Gecko/20100101 Firefox/10.0 "
        ] 
        self.WRITE_BATCH_SIZE=10
        self.MIGRATE_BATCH_SIZE=500


    def run(self):
        # --- Step 1: Read the list of CVE IDs ---
        csv_path = "./datasource/VulnerabilityNodes.csv"
        df = self._read_csv_with_fallback_encoding(csv_path)
        cveID_list = df['cveID'].tolist()
        if not cveID_list:
            raise ValueError("Could not read CSV file with any of the attempted encodings")
        print(f"Processing {len(cveID_list)} CVE IDs")

        # Add resumption capability
        completed_cves_file = "./datasource/completed_cves.txt"
        completed_cveids = set()
        
        if os.path.exists(completed_cves_file):
            with open(completed_cves_file, "r") as f:
                completed_cveids = set(line.strip() for line in f)
            print(f"Found {len(completed_cveids)} previously completed CVEs, will resume from there")
        
        # Filter out already completed ones
        remaining_cves = [cve for cve in cveID_list if cve not in completed_cveids]
        print(f"Remaining CVEs to process: {len(remaining_cves)} out of {len(cveID_list)}")
        
        # --- Step 2: Prepare output directories and files ---
        for file_path, file_header in zip(
            [self.vul_weakness_file, self.vul_domain_file, self.vul_product_file, self.affect_property_file], 
            [self.vul_weakness_header, self.vul_domain_header, self.vul_product_header, self.affect_property_header]
        ):
            # Create the directory for the file
            directory = os.path.dirname(file_path)
            os.makedirs(directory, exist_ok=True)
            
            # Check if the file exists, if not create it with the header
            if not os.path.exists(file_path):
                print(f"Creating new file: {file_path}")
                with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(file_header)
            else:
                print(f"File already exists: {file_path}")


        # --- Containers for the extracted data ---
        weakness_data = []  # for vul_weakness_file
        domain_data = []    # for vul_domain_file
        product_data = []   # for vul_product_file
        affect_data = [] # for affect_property_file

        # --- Step 3: Process each CVE ---
        for i, cveID in enumerate(remaining_cves):
            url = 'https://www.cvedetails.com/cve-details.php?cve_id=' + cveID
            print(f"\nCrawling details for {cveID} ({i+1}/{len(remaining_cves)}) from {url}")

            # time.sleep(random.uniform(0.01, 0.05))
            
            try:
                user_agent = random.choice(self.user_agents)
                headers = {'User-Agent': user_agent}
                r = requests.get(url, headers=headers)

                if r.status_code == 429:
                    print(f"⚠️ Rate limit exceeded (429). Sleeping for 60 seconds...")
                    time.sleep(60)
                else:
                    print(f"🟢 Successfully got the page for {cveID}")
                    
                # Extract page content
                html = r.text
                soup = BeautifulSoup(html, 'html.parser')
                h1_tag = soup.find('h1')
                is_invalid_page = not h1_tag or cveID not in h1_tag.get_text()
                if is_invalid_page: # This is most likely cvedetails do not provide any info about this cveID
                    print(f"❌ h1 check failed for {cveID}, likely not a valid page.\nDo not need to retrieve data from this cveID, adding to completed cveIDs.")
                    with open(completed_cves_file, "a") as f:
                        f.write(f"{cveID}\n")                
                    continue  # Skip this CVE
                
                # Extract data
                cwe_ids, vul_categories = self._crawl_data_for_vul_weakness_file(soup)
                weakness_data.append([cveID, cwe_ids, vul_categories])
                 
                # Write the domain data to CSV
                vul_domains = self._crawl_data_for_vul_domain_file(soup)               
                for vul_domain in vul_domains:
                    domain_data.append([cveID, vul_domain])
                
            
                # Write the product data to CSV
                vul_product_list: list[list[str]] = self._crawl_data_for_vul_product_file(soup)

                productlist_nversion_dict = {}  # Dictionary to count product occurrences; keys will be productName, value will be [vul_product_item, numOfVersion]

                for vul_product_item in vul_product_list:
                    productType, vendor, product, version = vul_product_item
                    
                    if product not in productlist_nversion_dict:
                        productlist_nversion_dict[product] = [vul_product_item, 1]
                    else:
                        productlist_nversion_dict[product][1] += 1


                # Add the product list and number of affected versions to the product_data list.
                for vul_productlist_nversion_item in productlist_nversion_dict.values():
                    productType, vendor, product, version = vul_productlist_nversion_item[0]
                    nversion = vul_productlist_nversion_item[1]
                    product_data.append([cveID, productType, vendor, product, nversion])

                # Also add the product and version to the affect_data list.
                for vul_product_item in vul_product_list:
                    productType, vendor, product, version = vul_product_item
                    affect_data.append([cveID, product, version])

                if i % self.WRITE_BATCH_SIZE == 0:
                    print(f"Writing the data into 4 CSV files...")
                    self._write_data_to_csv_and_clear_list(weakness_data, domain_data, product_data, affect_data)
                    
                # Record this CVE as completed
                with open(completed_cves_file, "a") as f:
                    f.write(f"{cveID}\n")

            except Exception as e:
                print(f"Error processing {cveID}: {e}")
                time.sleep(5)  # Brief pause after an error
                continue
        
        # Don't forget to write any remaining data
        if weakness_data:
            with open(self.vul_weakness_file, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerows(weakness_data)
        if domain_data:
            with open(self.vul_domain_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerows(domain_data)
        if product_data:
            with open(self.vul_product_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerows(product_data)
        if affect_data:
            with open(self.affect_property_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerows(affect_data)

    def migrate_data(self):
        self._migrate_vul_weakness_data()
        self._migrate_vul_domain_data()
        self._migrate_vul_product_data()
        self._migrate_affect_data()
    

    def _crawl_data_for_vul_weakness_file(self, soup) -> Tuple[str, str]:
        """
        Extract CWE IDs and vulnerability categories from the soup.
        Returns a tuple with:
        - A comma-joined string of just the CWE IDs (like 'CWE-20,CWE-79')
        - A comma-joined string of vulnerability categories
        """
        # Extract list of related CWE IDs
        cwe_ids = []
        cwe_section = soup.find('h2', id='cvedH2CWEs')
        if cwe_section:
            ul_tag = cwe_section.find_next('ul')
            if ul_tag:
                for li in ul_tag.find_all('li'):
                    a_tag = li.find('a')
                    if a_tag:
                        # Extract just the CWE-XX part using regex
                        full_text = a_tag.get_text(strip=True)
                        match = re.search(r'(CWE-\d+)', full_text)
                        if match:
                            cwe_ids.append(match.group(1))

        # Extract vulnerability categories
        cat_div = soup.find('div', id='cve_catslabelsnotes_div')
        if cat_div:
            # All <span> elements with class "ssc-vuln-cat" hold the category names
            categories = [span.get_text(strip=True) for span in cat_div.find_all('span', class_='ssc-vuln-cat')]
        else:
            categories = []
        
        # Join lists into comma-separated strings for CSV output
        cwe_ids_str = ','.join(cwe_ids)
        vulnerability_types = ','.join(categories)
        
        return cwe_ids_str, vulnerability_types
    
    def _crawl_data_for_vul_domain_file(self, soup) -> set:
        domains = set()
        ref_section = soup.find('h2', id='cvedH2References')
        if ref_section:
            ref_container = ref_section.find_next('div')
            if ref_container:
                ul_refs = ref_container.find('ul')
                if ul_refs:
                    for li in ul_refs.find_all('li'):
                        a_tag = li.find('a', href=True)
                        if a_tag:
                            url = a_tag['href']
                            parsed_url = urlparse(url)
                            domain = parsed_url.netloc
                            if domain:
                                domains.add(domain)
        return set(domains)

    def _crawl_data_for_vul_product_file(self, soup) -> list[list[str]]:
        """
        Extract affected product information from the CVE page soup.
        Returns a list of lists where each inner list is:
            [productType, vendor, product, version]
        - productType is determined by the CPE "part" field:
            'a' -> Application, 'o' -> Operating System, 'h' -> Hardware.
        - vendor and product are taken from the first two <a> tags.
        - version is extracted from the CPE string (position 5 after splitting by ":").
        """
        results = []
        affected_ul = soup.find('ul', id='affectedCPEsList')
        if affected_ul:
            for li in affected_ul.find_all('li'):
                # Extract vendor and product from the first <div>'s anchor tags.
                first_div = li.find('div')
                if not first_div:
                    continue
                a_tags = first_div.find_all('a')
                if len(a_tags) < 2:
                    continue
                vendor = a_tags[0].get_text(strip=True)
                product = a_tags[1].get_text(strip=True)
               
                # Get the CPE string from the div containing the CPE info.
                cpe_div = li.find('div', class_='col-md-8 text-secondary')
                if not cpe_div:
                    continue
                cpe_text = cpe_div.get_text(strip=True)
                # if not cpe_text.startswith("cpe:2.3:"):
                #     continue
                parts = cpe_text.split(':')
                if len(parts) < 6:
                    continue
                # parts[2] is the "part" code and parts[5] is the version.
                part_code = parts[2].lower()
                mapping = {'a': 'Application', 'o': 'Operating System', 'h': 'Hardware'}
                productType = mapping.get(part_code, "Unknown")
                version = parts[5]
                results.append([productType, vendor, product, version])
        return results

    def _write_data_to_csv_and_clear_list(self, weakness_data, domain_data, product_data, affect_data):
        print(f"Writing batch of {len(weakness_data)} records...")
        with open(self.vul_weakness_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerows(weakness_data)
        print(f"Writing batch of {len(domain_data)} records...")
        with open(self.vul_domain_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerows(domain_data)
        print(f"Writing batch of {len(product_data)} records...")
        with open(self.vul_product_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerows(product_data)
        print(f"Writing batch of {len(affect_data)} records...")
        with open(self.affect_property_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerows(affect_data)

        weakness_data.clear()  # Reset for new batch
        domain_data.clear()    # Reset for new batch
        product_data.clear()   # Reset for new batch
        affect_data.clear()   # Reset for new batch

    
    def _migrate_vul_weakness_data(self):
        """
        Migrates the vulnerability-weakness relationship data to Neo4j.
        
        1. Creates EXAMPLE_OF relationships between Vulnerability and Weakness nodes
        2. Adds vulnerabilityType property to Vulnerability nodes
        3. Processes in batches for efficiency
        4. Handles multiple CWE IDs per CVE
        """
        if not self.neo4j_driver:
            print("No Neo4j driver found. Please initialize the pipeline with a Neo4j driver.")
            return False
        
        try:
            df = self._read_csv_with_fallback_encoding(self.vul_weakness_file)
            
            def process_weakness_row(session, row):
                cve_id = row['cveID']
                cwe_ids = row['cweID'].split(',') if pd.notna(row['cweID']) else []
                vuln_type = row['vulnerabilityType'] if pd.notna(row['vulnerabilityType']) else ""
                vuln_type_list = [vt.strip() for vt in vuln_type.split(',')] if vuln_type else []
                
                if vuln_type_list:
                    self._safe_execute_query(
                        session,
                        "MATCH (v:Vulnerability {cveID: $cveID}) SET v.vulnerabilityType = $vulnerabilityType",
                        {'cveID': cve_id, 'vulnerabilityType': vuln_type_list},
                        f"updating Vulnerability {cve_id} properties"
                    )
                
                for cwe_id in cwe_ids:
                    cwe_id = cwe_id.strip().split('-')[1]
                    if cwe_id:
                        self._safe_execute_query(
                            session,
                            """
                            MATCH (v:Vulnerability {cveID: $cveID})
                            MATCH (w:Weakness {cweID: $cweID})
                            MERGE (v)-[r:EXAMPLE_OF]->(w)
                            """,
                            {'cveID': cve_id, 'cweID': cwe_id},
                            f"creating relationship for {cve_id}->{cwe_id}"
                        )
            
            self._process_in_batches(df, process_weakness_row, "vulnerability-weakness")
            print("Vulnerability-Weakness migration completed successfully")
            return True
            
        except Exception as e:
            print(f"Error during vulnerability-weakness migration: {e}")
            traceback.print_exc()
            return False

            
    def _migrate_vul_domain_data(self):
        """Migrates the vulnerability-domain relationship data to Neo4j."""
        if not self.neo4j_driver:
            return False
        
        try:
            df = self._read_csv_with_fallback_encoding(self.vul_domain_file)
            
            def process_domain_row(session, row):
                self._safe_execute_query(
                    session,
                    """
                    MATCH (v:Vulnerability {cveID: $cveID})
                    MATCH (d:Domain {domainName: $domainName})
                    MERGE (v)-[r:REFERS_TO]->(d)
                    """,
                    {'cveID': row['cveID'], 'domainName': row['domainName']},
                    f"creating relationship for {row['cveID']}->{row['domainName']}"
                )
            
            self._process_in_batches(df, process_domain_row, "vulnerability-domain")
            print("Vulnerability-Domain migration completed successfully")
            return True
            
        except Exception as e:
            print(f"Error during vulnerability-domain migration: {e}")
            traceback.print_exc()
            return False 


    def _migrate_vul_product_data(self):
        """Migrates the vulnerability-product relationship data to Neo4j."""
        if not self.neo4j_driver:
            return False
        
        try:
            df = self._read_csv_with_fallback_encoding(self.vul_product_file)
            
            def process_product_row(session, row):
                cve_id = row['cveID']
                product_name = row['productName']
                product_type = row['productType']
                num_of_version = int(row['numOfVersion']) if pd.notna(row['numOfVersion']) else None
                vendor_name = row['vendorName']
                
                # Create Product and AFFECTS relationship
                self._safe_execute_query(
                    session,
                    """
                    MERGE (p:Product {productName: $productName, productType: $productType})
                    WITH p
                    MATCH (v:Vulnerability {cveID: $cveID})
                    MERGE (v)-[r:AFFECTS]->(p)
                    ON CREATE SET r.numOfVersion = $numOfVersion
                    """,
                    {
                        'cveID': cve_id,
                        'productName': product_name,
                        'productType': product_type,
                        'numOfVersion': num_of_version
                    },
                    f"creating relationship for {cve_id}->{product_name}"
                )
                
                # Create Vendor and BELONGS_TO relationship
                self._safe_execute_query(
                    session,
                    """
                    MERGE (v:Vendor {vendorName: $vendorName})
                    WITH v
                    MATCH (p:Product {productName: $productName})
                    MERGE (p)-[r:BELONGS_TO]->(v)
                    """,
                    {'vendorName': vendor_name, 'productName': product_name},
                    f"creating vendor relationship for {product_name}->{vendor_name}"
                )
            
            self._process_in_batches(df, process_product_row, "vulnerability-product")
            print("Vulnerability-Product migration completed successfully")
            return True
            
        except Exception as e:
            print(f"Error during vulnerability-product migration: {e}")
            traceback.print_exc()
            return False


    def _migrate_affect_data(self):
        """
        Migrates the affect data to Neo4j.
        0. Create an empty affectedVersion list property for each AFFECTS relationship if not exists
        1. Creates AFFECTS relationships between Vulnerability and Product nodes
        2. Processes in batches for efficiency
        """
        if not self.neo4j_driver:
            print("No Neo4j driver found. Please initialize the pipeline with a Neo4j driver.")
            return False
        
        try:
            print(f"Reading affect data from {self.affect_property_file}")
            dataframe = self._read_csv_with_fallback_encoding(self.affect_property_file)
            
            self.update_affects_properties()

            def process_affect_row(session, row):
                self._safe_execute_query(session, """
                MATCH (v:Vulnerability {cveID: $cveID})-[r:AFFECTS]->(p:Product {productName: $productName})
                SET r.affectedVersion = r.affectedVersion + [$version]
                """, {
                    'cveID': row['cveID'],
                    'productName': row['productName'],
                    'version': row['version']
                },
                f"updating affect data for {row['cveID']}->{row['productName']}"
                )

            self._process_in_batches(dataframe, process_affect_row, "affect data")

        except Exception as e:
            print(f"Error during affect data migration: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        
    @staticmethod
    def _read_csv_with_fallback_encoding(file_path) -> pd.DataFrame:
        """Helper method to read CSV with multiple encoding attempts"""
        encodings_to_try = ['utf-8', 'utf-8-sig', 'latin1']
        for encoding in encodings_to_try:
            try:
                df = pd.read_csv(file_path, encoding=encoding)
                return df
            except UnicodeDecodeError:
                print(f"Failed with {encoding}, trying next...")
        return None    
    
    
    def _process_in_batches(self, dataframe: pd.DataFrame, process_row_func, description: str):
        """Helper method to process dataframe in batches"""
        if dataframe is None or dataframe.empty:
            raise ValueError(f"Could not read {description} data")
    
        total_rows = len(dataframe)
        print(f"Found {total_rows} {description} entries")
        batches = (total_rows + self.MIGRATE_BATCH_SIZE - 1) // self.MIGRATE_BATCH_SIZE
        
        for batch_num in range(batches):
            start_idx = batch_num * self.MIGRATE_BATCH_SIZE
            end_idx = min(start_idx + self.MIGRATE_BATCH_SIZE, total_rows)
            
            print(f"Processing batch {batch_num+1}/{batches} (rows {start_idx+1}-{end_idx})")
            batch_df = dataframe.iloc[start_idx:end_idx]
            
            with self.neo4j_driver.session() as session:
                for _, row in batch_df.iterrows():
                    process_row_func(session, row)
            
            print(f"Completed batch {batch_num+1}")
    
    
    def _safe_execute_query(self, session, query, params, error_msg):
        """Helper method to execute Neo4j queries with error handling
        
        Args:
            session: Neo4j session
            query: Cypher query string
            params: Query parameters
            error_msg: Error message prefix for logging
        """
        try:
            result = session.run(query, params)
            return result
        except Exception as e:
            if not ("ConstraintValidationFailed" in str(e) or "already exists with label" in str(e)):
                print(f"Error: {error_msg}: {e}")
            return None

    def update_affects_properties(self):
        """Updates AFFECTS relationship properties using modern Neo4j syntax"""
        with self.neo4j_driver.session() as session:
            session.run("""
            MATCH ()-[r:AFFECTS]->()
            WHERE r.affectedVersion IS NULL
            SET r.affectedVersion = []
            """)

if __name__ == "__main__":
    neo4j_driver = neo4j.GraphDatabase.driver(uri="bolt://localhost:7687", auth=("neo4j", "Vanly180705!"))
    cve_details_pipeline = CVEDetailsPipeline(neo4j_driver)
    # cve_details_pipeline.run()
    cve_details_pipeline.migrate_data()