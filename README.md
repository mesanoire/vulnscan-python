# vulnscan-python
Vulnerability database parser (not actually a scanner)
## Description
VulnScan takes a URL from one of its accepted data sources (currently only Snyk's Vuln DB for NPM packages), then outputs information about
its risk factors (MTTP, number of total vulns in the package, etc)
## Installation
* Install latest version of python (https://www.python.org/downloads/)
* Run the following command 'pip install bs4 requests numpy'
* Run the scanner with 'python vulnscan.py **URL**'

