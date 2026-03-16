// #######################################################
//              VulKG Project - Neo4j Import Script
// #######################################################

//========================================================
//  1. SETUP: Constraints & Indexes
//========================================================

// ---- Uniqueness Constraints ----
CREATE CONSTRAINT UniqueCveID IF NOT EXISTS ON (v:Vulnerability) ASSERT v.cveID IS UNIQUE;
CREATE CONSTRAINT UniqueEID IF NOT EXISTS ON (e:Exploit) ASSERT e.eid IS UNIQUE;
CREATE CONSTRAINT UniqueAuthorName IF NOT EXISTS ON (a:Author) ASSERT a.authorName IS UNIQUE;
CREATE CONSTRAINT UniquecweID IF NOT EXISTS ON (w:Weakness) ASSERT w.cweID IS UNIQUE;
CREATE CONSTRAINT UniqueDomainName IF NOT EXISTS ON (d:Domain) ASSERT d.domainName IS UNIQUE;
CREATE CONSTRAINT UniqueProductName IF NOT EXISTS ON (p:Product) ASSERT p.productName IS UNIQUE;
CREATE CONSTRAINT UniqueVendorName IF NOT EXISTS ON (v:Vendor) ASSERT v.vendorName IS UNIQUE;

// ---- Verify Constraints ----
CALL db.constraints();

//========================================================
//  2. LOAD DATA: Nodes
//========================================================

// ---- Load Vulnerability Nodes ----
CALL apoc.periodic.iterate(
  "CALL apoc.load.csv('file:///VulnerabilityNodes.csv') YIELD map AS row RETURN row",
  "MERGE (v:Vulnerability {cveID: row.cveID})
   ON CREATE SET 
     v.publishedDate = date(row.publishedDate),
     v.description = row.description_value,
     v.numOfReference = toInteger(row.num_reference),
     v.v2baseScore = toFloat(row.v2baseScore),
     v.v3baseScore = toFloat(row.v3baseScore),
     v.v2vectorString = row.v2vectorString,
     v.v3vectorString = row.v3vectorString,
     v.v2impactScore = toInteger(row.v2impactScore),
     v.v3impactScore = toInteger(row.v3impactScore)",
  {batchSize:500}
);

// ---- Load Exploit Nodes ----
CALL apoc.periodic.iterate(
  "CALL apoc.load.csv('file:///ExploitNodes.csv') YIELD map AS row RETURN row",
  "MERGE (e:Exploit {eid: row.ExploitID})
   ON CREATE SET 
     e.exploitPublishDate = date(row.Exploit_Date),
     e.exploitType = row.Exploit_Type,
     e.platform = row.Platform",
  {batchSize:500}
);

// ---- Load Author Nodes ----
CALL apoc.periodic.iterate(
  "CALL apoc.load.csv('file:///ExploitNodes.csv') YIELD map AS row RETURN row",
  "MERGE (a:Author {authorName: row.Author})",
  {batchSize:500}
);

// ---- Load Weakness Nodes ----
CALL apoc.periodic.iterate(
  "CALL apoc.load.csv('file:///WeaknessNodes.csv') YIELD map AS row RETURN row",
  "MERGE (w:Weakness {cweID: row.cweID})
   ON CREATE SET 
     w.cweView = split(row.cweView,','),
     w.cweName = row.cweName,
     w.description = row.description",
  {batchSize:500}
);

// ---- Load Domain Nodes ----
CALL apoc.periodic.iterate(
  "CALL apoc.load.csv('file:///DomainNodes_Vulnerability_HAS_REFERENCE_Domain_relationship.csv') YIELD map AS row RETURN row",
  "MERGE (d:Domain {domainName: row.domainName})",
  {batchSize:500}
);

// ---- Load Product Nodes ----
CALL apoc.periodic.iterate(
  "CALL apoc.load.csv('file:///ProductNodes_VendorNodes_Vulnerability_AFFECTS_Product_BELONGS_TO_Vendor.csv') YIELD map AS row RETURN row",
  "MERGE (p:Product {productName: row.Product})
   ON CREATE SET p.productType = row.ProductType",
  {batchSize:500}
);

// ---- Load Vendor Nodes ----
CALL apoc.periodic.iterate(
  "CALL apoc.load.csv('file:///ProductNodes_VendorNodes_Vulnerability_AFFECTS_Product_BELONGS_TO_Vendor.csv') YIELD map AS row RETURN row",
  "MERGE (v:Vendor {vendorName: row.Vendor})",
  {batchSize:500}
);

//========================================================
//  3. LOAD DATA: Relationships
//========================================================

// ---- Author WRITES Exploit ----
CALL apoc.periodic.iterate(
  "CALL apoc.load.csv('file:///ExploitNodes.csv') YIELD map AS row RETURN row",
  "MATCH (e:Exploit {eid: row.ExploitID})
   MATCH (a:Author {authorName: row.Author})
   MERGE (a)-[:WRITES]->(e)",
  {batchSize:500}
);

// ---- Exploit EXPLOITS Vulnerability ----
CALL apoc.periodic.iterate(
  "CALL apoc.load.csv('file:///Vulnerability_HAS_EXPLOIT_Exploit_relationship.csv') YIELD map AS row RETURN row",
  "MATCH (e:Exploit {eid: row.eid})
   MATCH (v:Vulnerability {cveID: row.cveID})
   MERGE (e)-[:EXPLOITS]->(v)",
  {batchSize:500}
);

// ---- Vulnerability EXAMPLE_OF Weakness ----
CALL apoc.periodic.iterate(
  "CALL apoc.load.csv('file:///VulnerabilityNodesAddProperties.csv') YIELD map AS row RETURN row",
  "MATCH (v:Vulnerability {cveID: row.cveID})
   MATCH (w:Weakness {cweID: row.CWEID})
   MERGE (v)-[:EXAMPLE_OF]->(w)",
  {batchSize:500}
);

// ---- Vulnerability REFERS_TO Domain ----
CALL apoc.periodic.iterate(
  "CALL apoc.load.csv('file:///DomainNodes_Vulnerability_HAS_REFERENCE_Domain_relationship.csv') YIELD map AS row RETURN row",
  "MATCH (v:Vulnerability {cveID: row.cveID})
   MATCH (d:Domain {domainName: row.domainName})
   MERGE (v)-[:REFERS_TO]->(d)",
  {batchSize:500}
);

// ---- Vulnerability AFFECTS Product ----
CALL apoc.periodic.iterate(
  "CALL apoc.load.csv('file:///ProductNodes_VendorNodes_Vulnerability_AFFECTS_Product_BELONGS_TO_Vendor.csv') YIELD map AS row RETURN row",
  "MATCH (v:Vulnerability {cveID: row.cveID})
   MATCH (p:Product {productName: row.Product})
   MERGE (v)-[:AFFECTS]->(p)",
  {batchSize:500}
);

// ---- Product BELONGS_TO Vendor ----
CALL apoc.periodic.iterate(
  "CALL apoc.load.csv('file:///ProductNodes_VendorNodes_Vulnerability_AFFECTS_Product_BELONGS_TO_Vendor.csv') YIELD map AS row RETURN row",
  "MATCH (p:Product {productName: row.Product})
   MATCH (v:Vendor {vendorName: row.Vendor})
   MERGE (p)-[:BELONGS_TO]->(v)",
  {batchSize:500}
);

//========================================================
//  4. INDEXING FOR PERFORMANCE
//========================================================

// ---- Indexes for fast searching ----
CREATE INDEX VulnerabilityPublishedDate IF NOT EXISTS FOR (v:Vulnerability) ON (v.publishedDate);
CREATE INDEX ExploitPublishDate IF NOT EXISTS FOR (e:Exploit) ON (e.exploitPublishDate);
CREATE FULLTEXT INDEX VulnerabilityDescriptionFullTextSchema IF NOT EXISTS FOR (v:Vulnerability) ON EACH [v.description];


//========================================================
//  5. CLEANUP: Deleting Unwanted Data
//========================================================

// ---- Delete vulnerabilities with **REJECT** in description ----
MATCH (n:Vulnerability)
WHERE n.description STARTS WITH '** REJECT **'
DETACH DELETE n;

//========================================================
//  6. STATISTICS & VALIDATION
//========================================================

MATCH (n:Vulnerability) RETURN count(n); 
MATCH (n:Exploit) RETURN count(n);
MATCH (n:Weakness) RETURN count(n);
MATCH (n:Product) RETURN count(n);
MATCH (n:Vendor) RETURN count(n);
MATCH (n:Author) RETURN count(n);
MATCH (n:Domain) RETURN count(n);

MATCH ()-[r:EXPLOITS]->() RETURN count(r);
MATCH ()-[r:AFFECTS]->() RETURN count(r);
MATCH ()-[r:BELONGS_TO]->() RETURN count(r);
MATCH ()-[r:EXAMPLE_OF]->() RETURN count(r);
MATCH ()-[r:WRITES]->() RETURN count(r);
MATCH ()-[r:REFERS_TO]->() RETURN count(r);
