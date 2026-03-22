CONSTRAINTS = {
    "UniqueCveID": "CREATE CONSTRAINT UniqueCveID IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cveID IS UNIQUE;",
    "UniqueEID": "CREATE CONSTRAINT UniqueEID IF NOT EXISTS FOR (e:Exploit) REQUIRE e.eid IS UNIQUE;",
    "UniqueAuthorName": "CREATE CONSTRAINT UniqueAuthorName IF NOT EXISTS FOR (a:Author) REQUIRE a.authorName IS UNIQUE;",
    "UniquecweID": "CREATE CONSTRAINT UniquecweID IF NOT EXISTS FOR (w:Weakness) REQUIRE w.cweID IS UNIQUE;",
    "UniqueDomainName": "CREATE CONSTRAINT UniqueDomainName IF NOT EXISTS FOR (d:Domain) REQUIRE d.domainName IS UNIQUE;",
    "UniqueProductName": "CREATE CONSTRAINT UniqueProductName IF NOT EXISTS FOR (p:Product) REQUIRE p.productName IS UNIQUE;",
    "UniqueVendorName": "CREATE CONSTRAINT UniqueVendorName IF NOT EXISTS FOR (v:Vendor) REQUIRE v.vendorName IS UNIQUE;"
}

INDEXES = {
    "VulnerabilityV2version": "CREATE INDEX VulnerabilityV2version IF NOT EXISTS FOR (v:Vulnerability) ON (v.v2version)",
    "VulnerabilityV3version": "CREATE INDEX VulnerabilityV3version IF NOT EXISTS FOR (v:Vulnerability) ON (v.v3version)",
    "VulnerabilityPublishedDate": "CREATE INDEX VulnerabilityPublishedDate IF NOT EXISTS FOR (v:Vulnerability) ON (v.publishedDate)",
    "VulnerabilityDescription": "CREATE INDEX VulnerabilityDescription IF NOT EXISTS FOR (v:Vulnerability) ON (v.description)",
    "ExploitExploitPublishDate": "CREATE INDEX ExploitExploitPublishDate IF NOT EXISTS FOR (e:Exploit) ON (e.exploitPublishDate)",
    "VulnerabilityDescriptionFullTextSchema": "CREATE FULLTEXT INDEX VulnerabilityDescriptionFullTextSchema IF NOT EXISTS FOR (v:Vulnerability) ON EACH [v.description]"
}
