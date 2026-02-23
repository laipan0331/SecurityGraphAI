"""
SecurityGraph AI - Step 1: Data Collection
Collect CVE vulnerability data from NVD (National Vulnerability Database)
"""

import requests
import pandas as pd
import time
from datetime import datetime

class CVEDataCollector:
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
    def fetch_cves_by_keyword(self, keyword, max_results=10):
        """Search for CVEs by keyword"""
        print(f"\nSearching: {keyword}")
        print("-" * 50)
        
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results
        }
        
        try:
            response = requests.get(self.base_url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                print(f"✓ Found {len(vulnerabilities)} CVE records")
                return vulnerabilities
            else:
                print(f"✗ Error: HTTP {response.status_code}")
                return []
                
        except Exception as e:
            print(f"✗ Request failed: {str(e)}")
            return []
    
    def parse_cve_data(self, cve_item):
        """Parse CVE JSON data"""
        cve = cve_item.get("cve", {})
        
        # 提取CVE ID
        cve_id = cve.get("id", "")
        
        # 提取描述
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        # 提取CVSS评分
        metrics = cve.get("metrics", {})
        cvss_score = None
        severity = None
        
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss_v31 = metrics["cvssMetricV31"][0]
            cvss_score = cvss_v31.get("cvssData", {}).get("baseScore")
            severity = cvss_v31.get("cvssData", {}).get("baseSeverity")
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss_v2 = metrics["cvssMetricV2"][0]
            cvss_score = cvss_v2.get("cvssData", {}).get("baseScore")
            if cvss_score:
                if cvss_score >= 9.0:
                    severity = "CRITICAL"
                elif cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
        
        # 提取发布日期
        published = cve.get("published", "")
        
        # 提取CWE ID
        weaknesses = cve.get("weaknesses", [])
        cwe_ids = []
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                cwe_id = desc.get("value", "")
                if cwe_id.startswith("CWE-"):
                    cwe_ids.append(cwe_id)
        
        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "published_date": published,
            "cwe_ids": ", ".join(cwe_ids) if cwe_ids else None
        }
    
    def collect_security_dataset(self):
        """Collect security dataset"""
        keywords = [
            "SQL injection",
            "Cross-site scripting",
            "Cross-site request forgery",
            "Remote code execution",
            "Authentication bypass",
            "Path traversal",
            "Command injection",
            "XML external entity",
            "Insecure deserialization",
            "Server-side request forgery"
        ]
        
        all_records = []
        
        for i, keyword in enumerate(keywords):
            print(f"\nProgress: {i+1}/{len(keywords)}")
            
            cves = self.fetch_cves_by_keyword(keyword, max_results=10)
            
            for cve_item in cves:
                record = self.parse_cve_data(cve_item)
                all_records.append(record)
            
            if i < len(keywords) - 1:
                print("Waiting 6 seconds...")
                time.sleep(6)
        
        df = pd.DataFrame(all_records)
        df = df.drop_duplicates(subset=['cve_id'])
        
        print(f"\n" + "=" * 50)
        print(f"✓ Data collection complete!")
        print(f"✓ Collected {len(df)} unique CVE records")
        print("=" * 50)
        
        return df
    
    def save_data(self, df, filename):
        """Save data"""
        filepath = f"data/{filename}"
        df.to_csv(filepath, index=False, encoding='utf-8-sig')
        print(f"\n✓ Data saved to: {filepath}")


if __name__ == "__main__":
    print("=" * 50)
    print("SecurityGraph AI - Data Collection")
    print("=" * 50)
    
    collector = CVEDataCollector()
    df = collector.collect_security_dataset()
    
    print("\nData Statistics:")
    print(f"  Total records: {len(df)}")
    print(f"  Severity distribution:")
    if 'severity' in df.columns:
        for severity, count in df['severity'].value_counts().items():
            print(f"    {severity}: {count}")
    
    print("\nFirst 3 records preview:")
    print(df.head(3)[['cve_id', 'severity', 'cvss_score']])
    
    collector.save_data(df, "raw_cves.csv")
    
    print("\n✓ Step 1 Complete!")
    print("Next step: Run python etl/02_preprocess_data.py")