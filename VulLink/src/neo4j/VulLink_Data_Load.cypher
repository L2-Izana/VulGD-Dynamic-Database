// 1️⃣ Drop Constraints for Faster Import
DROP CONSTRAINT UniqueCveID IF EXISTS;
DROP CONSTRAINT UniqueEID IF EXISTS;
DROP CONSTRAINT UniqueAuthorName IF EXISTS;
DROP CONSTRAINT UniquecweID IF EXISTS;
DROP CONSTRAINT UniqueDomainName IF EXISTS;
DROP CONSTRAINT UniqueProductName IF EXISTS;
DROP CONSTRAINT UniqueVendorName IF EXISTS;

// 2️⃣ Import Vulnerabilities
CALL apoc.periodic.iterate(
  "LOAD CSV WITH HEADERS FROM 'file:///VulnerabilityNodes.csv' AS row RETURN row",
  "
  MERGE (v:Vulnerability {cveID: row.cveID})
  ON CREATE SET
    v.publishedDate = date(row.publishedDate),
    v.description = row.description_value,
    v.numOfReference = toInteger(row.num_reference),
    v.v2version = toInteger(row.v2version),
    v.v2baseScore = toFloat(row.v2baseScore),
    v.v3baseScore = toFloat(row.v3baseScore),
    v.v3vectorString = row.v3vectorString
  ",
  {batchSize: 2000, parallel: true, retries: 3, failedBatchLogging: true}
);

// 3️⃣ Import Exploits
CALL apoc.periodic.iterate(
  "LOAD CSV WITH HEADERS FROM 'file:///ExploitNodes.csv' AS row RETURN row",
  "
  MERGE (e:Exploit {eid: row.ExploitID})
  ON CREATE SET
    e.exploitPublishDate = date(row.Exploit_Date),
    e.exploitType = row.Exploit_Type,
    e.platform = row.Platform
  ",
  {batchSize: 2000, parallel: true, retries: 3, failedBatchLogging: true}
);

// 4️⃣ Import Authors
CALL apoc.periodic.iterate(
  "LOAD CSV WITH HEADERS FROM 'file:///ExploitNodes.csv' AS row RETURN row",
  "
  MERGE (a:Author {authorName: row.Author})
  ",
  {batchSize: 2000, parallel: true, retries: 3, failedBatchLogging: true}
);

// 5️⃣ Create Relationships (Author WRITES Exploit)
CALL apoc.periodic.iterate(
  "LOAD CSV WITH HEADERS FROM 'file:///ExploitNodes.csv' AS row RETURN row",
  "
  MATCH (e:Exploit {eid: row.ExploitID}), (a:Author {authorName: row.Author})
  MERGE (a)-[:WRITES]->(e)
  ",
  {batchSize: 2000, parallel: true, retries: 3, failedBatchLogging: true}
);

// 6️⃣ Import Weaknesses
CALL apoc.periodic.iterate(
  "LOAD CSV WITH HEADERS FROM 'file:///WeaknessNodes.csv' AS row RETURN row",
  "
  MERGE (w:Weakness {cweID: row.cweID})
  ON CREATE SET
    w.cweView = split(row.cweView, ','),
    w.cweName = row.cweName,
    w.weaknessAbstraction = row.weaknessAbstraction,
    w.status = row.status,
    w.description = row.description,
    w.extendedDescription = row.extendedDescription
  ",
  {batchSize: 2000, parallel: true, retries: 3, failedBatchLogging: true}
);

// 7️⃣ Create Relationships (Vulnerability EXAMPLE_OF Weakness)
CALL apoc.periodic.iterate(
  "LOAD CSV WITH HEADERS FROM 'file:///VulnerabilityNodesAddProperties.csv' AS row RETURN row",
  "
  MATCH (v:Vulnerability {cveID: row.cveID}), (w:Weakness {cweID: row.CWEID})
  MERGE (v)-[:EXAMPLE_OF]->(w)
  ",
  {batchSize: 2000, parallel: true, retries: 3, failedBatchLogging: true}
);

// 8️⃣ Create Constraints After Import
CREATE CONSTRAINT UniqueCveID IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cveID IS UNIQUE;
CREATE CONSTRAINT UniqueEID IF NOT EXISTS FOR (e:Exploit) REQUIRE e.eid IS UNIQUE;
CREATE CONSTRAINT UniqueAuthorName IF NOT EXISTS FOR (a:Author) REQUIRE a.authorName IS UNIQUE;
CREATE CONSTRAINT UniquecweID IF NOT EXISTS FOR (w:Weakness) REQUIRE w.cweID IS UNIQUE;
CREATE CONSTRAINT UniqueDomainName IF NOT EXISTS FOR (d:Domain) REQUIRE d.domainName IS UNIQUE;
CREATE CONSTRAINT UniqueProductName IF NOT EXISTS FOR (p:Product) REQUIRE p.productName IS UNIQUE;
CREATE CONSTRAINT UniqueVendorName IF NOT EXISTS FOR (v:Vendor) REQUIRE v.vendorName IS UNIQUE;

// 9️⃣ Create Indexes for Faster Queries
CREATE INDEX VulnerabilityPublishedDate IF NOT EXISTS FOR (v:Vulnerability) ON (v.publishedDate);
CREATE INDEX ExploitPublishDate IF NOT EXISTS FOR (e:Exploit) ON (e.exploitPublishDate);
CREATE INDEX WeaknessName IF NOT EXISTS FOR (w:Weakness) ON (w.cweName);

RETURN "✅ Optimized Data Import, Constraints, and Indexes Created Successfully!";
