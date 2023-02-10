import requests
from bs4 import BeautifulSoup
import numpy as np
import sys
import re
import datetime

def getMTTP(vulns: dict) -> float:
    total = 0
    if len(vulns) == 0:
      return -1;
    for k, v in vulns.items():
      total = float(total + v)
    return total / len(vulns)

def getNumVulns(vulns: dict) -> int:
    return len(vulns)

def getDateTime(dateRaw: str):
    months = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}
    date = re.search(r'\b(\d{1,2})\s([A-Z][a-z]{2}),?\s(\d{4})\b', dateRaw)
    day = int(date.group(1))
    month = months[date.group(2)]
    year = int(date.group(3))
    return datetime.datetime(year,month,day)


"""
Handler for Snyk.io data sources. Big gross and ugly.

@param url The URL of the snyk vuln DB page
@return A list containing each vulnerability, and the number of days it took to patch
"""
def parseSnyk(url: str) -> dict:
    vulns = {}
    response = requests.get(url)
    raw = BeautifulSoup(response.content, "html.parser")
    vulnTable = raw.find("table", {"data-snyk-test": "PackageVulnerabilitiesTable: table"})
    for row in vulnTable.find_all("tr"):
      aTag = row.find("a")
      if aTag:
        link = aTag["href"]
      else:
        continue
      vulnResponse = requests.get("https://security.snyk.io/" + link)
      vulnRaw = BeautifulSoup(vulnResponse.content, "html.parser")
      try:
        vulnName = vulnRaw.find("a", id=re.compile("^CVE-.*")).text.split()[0]
      except:
        vulnName = "CVE not found"
      startDateRaw = vulnRaw(text=re.compile("Introduced"))
      vulnStartDate = getDateTime(startDateRaw[0])
      vulnVersionRaw = row.find_all("span", {"data-snyk-test": "VulnerableVersions: version"})[-1].text
      vulnVersionEnd = vulnVersionRaw.split()[-1]
      vulnVersionEnd = re.search(r"(\d+\.\d+\.\d+|\*|\d+(\.\d+){2})", vulnVersionEnd).group(1)
      if vulnVersionEnd == "*":
        tod = datetime.date.today()
        vulnEndDate = datetime.datetime(tod.year,tod.month,tod.day)
      else:
        vulnEndDate = getDateTime(raw.find("span", {"version": vulnVersionEnd}).text)
      timeToPatch = (vulnEndDate - vulnStartDate).days
      print("TTP: " + str(timeToPatch) + " days")
      print("Name: " + vulnName)
      if timeToPatch < 0:
        continue
      vulns[vulnName] = timeToPatch
    return vulns

def printBanner():
    print("====================================================================================")
    print(" █████   █████            ████              █████████                               ")
    print("░░███   ░░███            ░░███             ███░░░░░███                              ")
    print(" ░███    ░███  █████ ████ ░███  ████████  ░███    ░░░   ██████   ██████   ████████  ")
    print(" ░███    ░███ ░░███ ░███  ░███ ░░███░░███ ░░█████████  ███░░███ ░░░░░███ ░░███░░███ ")
    print(" ░░███   ███   ░███ ░███  ░███  ░███ ░███  ░░░░░░░░███░███ ░░░   ███████  ░███ ░███ ")
    print("  ░░░█████░    ░███ ░███  ░███  ░███ ░███  ███    ░███░███  ███ ███░░███  ░███ ░███ ")
    print("    ░░███      ░░████████ █████ ████ █████░░█████████ ░░██████ ░░████████ ████ █████")
    print("     ░░░        ░░░░░░░░ ░░░░░ ░░░░ ░░░░░  ░░░░░░░░░   ░░░░░░   ░░░░░░░░ ░░░░ ░░░░░ ")
    print("====================================================================================")
    print("\nJacob West, 2023\n\n\n")

def domainChecker(url: str, domains: list[str]) -> bool:
    pattern = re.compile(r'^(https?:\/\/)?([a-zA-Z0-9.-]+)(\/[a-zA-Z0-9-]+)(\/[a-zA-Z0-9-]+).*')
    match = pattern.match(url)

    """How many subpages deep do we need to check? Matches up 1-1 to domains"""
    deep = {"security.snyk.io":2}
    domain = ""
    if match:
      for i in range(2, 3 + deep[match.group(2)]):
        domain = domain + match.group(i)
      return domains.count(domain) > 0
    return None

"""
Main function. Verifies domain and command line args, then goes ahead and scrapes the url.

"""
if __name__ == "__main__":
    printBanner()
    domains = ["security.snyk.io/package/npm"]
    if len(sys.argv) != 2:
        print("Usage: python VulnScan.py <URL>")
        sys.exit(1)
    vulns = {}
    url = sys.argv[1]
    
    if domainChecker(url, domains):
        vulns = parseSnyk(url)
    else:
        print("Your domain is not in the accepted data source list.")
        print("Snyk NPM packages are currently the only data source this program handles.")
        sys.exit("Enter a correct domain")
    
    MTTP = getMTTP(vulns)
    numVulns = getNumVulns(vulns)
    print("Mean time to patch: {:.2f} days".format(MTTP))
    print("Total number of Vulnerabilities: {}".format(numVulns))
