from setuptools import setup, find_packages

setup(
    name="vullink-migration",
    version="1.0.0",
    description="VulLink Neo4j Migration Tool",
    author="VulLink Team",
    packages=find_packages(),
    install_requires=[
        "neo4j>=4.4.0",
    ],
    entry_points={
        "console_scripts": [
            "vullink-migrate=migration.main:main",
        ],
    },
    python_requires=">=3.6",
) 