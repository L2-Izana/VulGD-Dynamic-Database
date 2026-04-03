import csv
from urllib.request import urlopen
import os

from bs4 import BeautifulSoup
import neo4j


class CVEPipeline:
    def __init__(self, neo4j_driver: neo4j.GraphDatabase.driver):
        self.neo4j_driver = neo4j_driver
        os.makedirs("./datasource", exist_ok=True)  
        self.saved_df = "./datasource/Vulnerability_HAS_EXPLOIT_Exploit_relationship.csv"

    def run(self):
        url='http://cve.mitre.org/data/refs/refmap/source-EXPLOIT-DB.html'
        html = urlopen(url)
        bsObj = BeautifulSoup(html, features="lxml")  # parser LXML turn the data source into a beautifulSour object

        table = bsObj.findAll("table")[3]
        rows = table.findAll('tr')
        exploit_list = [["eid","cveID"]]

        for row in rows[0:len(rows)-1]: #the last row is not
            cells = row.findAll(['td'])
            expID = cells[0].get_text()
            is_unidentified_exploit = expID == "EXPLOIT-DB:Exploit Database"
            if is_unidentified_exploit:
                continue
            cveID = cells[1].get_text().strip()
            cveID = cveID.replace('\n', ';')
            cveIDs= cveID.split() 
            for cveID in cveIDs:
                exploit_list.append([expID,cveID])
        print("the number of items in the oupput file:"+str(len(exploit_list)))
        with open(self.saved_df, 'w') as csvwf:
            writer = csv.writer(csvwf, lineterminator='\n')  #
            writer.writerows(exploit_list)

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
    cve_pipeline.migrate_data()





