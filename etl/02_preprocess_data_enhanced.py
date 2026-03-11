"""
SecurityGraph AI - Step 2: Enhanced Data Preprocessing
Extract structured fields from CVE data for graph database relationships
- Software name/vendor
- Affected versions
- Vulnerability type
- Attack vector
"""

import pandas as pd
import re
import nltk
from nltk.tokenize import word_tokenize, sent_tokenize
from nltk.corpus import stopwords
import string

class EnhancedSecurityPreprocessor:
    def __init__(self):
        self.stop_words = set(stopwords.words('english'))
        
        # Vulnerability type patterns
        self.vulnerability_patterns = {
            'SQL Injection': r'(?i)(sql\s+injection|sqli|sql\s+code\s+injection)',
            'Cross-Site Scripting': r'(?i)(cross[\s-]?site\s+scripting|xss)',
            'Cross-Site Request Forgery': r'(?i)(cross[\s-]?site\s+request\s+forgery|csrf|xsrf)',
            'Remote Code Execution': r'(?i)(remote\s+code\s+execution|rce|execute\s+arbitrary\s+code|arbitrary\s+code\s+execution)',
            'Command Injection': r'(?i)(command\s+injection|os\s+command|arbitrary\s+commands)',
            'XML External Entity': r'(?i)(xml\s+external\s+entity|xxe)',
            'Insecure Deserialization': r'(?i)(insecure\s+deserialization|deserialization)',
            'Server-Side Request Forgery': r'(?i)(server[\s-]?side\s+request\s+forgery|ssrf)',
            'Authentication Bypass': r'(?i)(authentication\s+bypass|bypass\s+authentication)',
            'Path Traversal': r'(?i)(path\s+traversal|directory\s+traversal)',
            'Buffer Overflow': r'(?i)(buffer\s+overflow|stack\s+overflow)',
            'Privilege Escalation': r'(?i)(privilege\s+escalation|escalate\s+privileges)',
            'Denial of Service': r'(?i)(denial[\s-]?of[\s-]?service|dos\s+attack)',
            'Information Disclosure': r'(?i)(information\s+disclosure|sensitive\s+information)',
        }
        
        # Attack vector patterns
        self.attack_vector_patterns = {
            'Remote': r'(?i)\b(remote|remotely)\b',
            'Network': r'(?i)\b(network|via\s+network)\b',
            'Local': r'(?i)\b(local|locally)\b',
            'Physical': r'(?i)\b(physical|physical\s+access)\b',
            'Adjacent': r'(?i)\b(adjacent|adjacent\s+network)\b',
        }
        
        # Software/vendor extraction patterns
        self.software_patterns = [
            # Pattern: "Software Version" (e.g., "Apache 2.4.1")
            r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s+(\d+\.\d+(?:\.\d+)*)',
            # Pattern: "in Software" (e.g., "in phpBB")
            r'\bin\s+([A-Z][A-Za-z0-9]+(?:\s+[A-Z][A-Za-z0-9]+)*)',
            # Pattern: "Software for/by" (e.g., "MySQL for Linux")
            r'\b([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*)\s+(?:for|by)',
        ]
        
        # Version pattern
        self.version_pattern = r'v?(\d+\.\d+\.?\d*(?:\.\d+)?(?:\s*(?:[a-zA-Z]+\d*|RC\d*|beta\d*))?)'
        
    def extract_software_name(self, text):
        """Extract software name from CVE description"""
        if not text:
            return None
        
        software_names = []
        
        # Try all software patterns
        for pattern in self.software_patterns:
            matches = re.findall(pattern, text)
            if matches:
                if isinstance(matches[0], tuple):
                    software_names.extend([m[0].strip() for m in matches if m[0]])
                else:
                    software_names.extend([m.strip() for m in matches if m])
        
        # Known software keywords
        known_software = [
            'Apache', 'Oracle', 'Microsoft', 'Linux', 'Windows', 'MySQL', 'PostgreSQL',
            'PHP', 'Java', 'Python', 'Ruby', 'Node.js', 'WordPress', 'Drupal', 'Joomla',
            'phpBB', 'Bugzilla', 'Jenkins', 'Tomcat', 'IIS', 'nginx', 'OpenSSL',
            'jQuery', 'Angular', 'React', 'Django', 'Spring', 'Struts', 'Log4j',
            'Chrome', 'Firefox', 'Safari', 'Edge', 'Cisco', 'Adobe', 'IBM', 'SAP'
        ]
        
        # Check if any known software appears in text
        for software in known_software:
            if re.search(r'\b' + re.escape(software) + r'\b', text, re.IGNORECASE):
                if software not in software_names:
                    software_names.append(software)
        
        # Return the most likely software name (first match or None)
        return software_names[0] if software_names else None
    
    def extract_affected_versions(self, text):
        """Extract version numbers from CVE description"""
        if not text:
            return None
        
        versions = re.findall(self.version_pattern, text, re.IGNORECASE)
        
        # Deduplicate and clean
        versions = list(dict.fromkeys(versions))
        
        return ', '.join(versions) if versions else None
    
    def extract_vulnerability_type(self, text):
        """Extract vulnerability type from CVE description"""
        if not text:
            return None
        
        detected_types = []
        
        for vuln_type, pattern in self.vulnerability_patterns.items():
            if re.search(pattern, text):
                detected_types.append(vuln_type)
        
        # Return primary vulnerability type (first match)
        return detected_types[0] if detected_types else None
    
    def extract_attack_vector(self, text):
        """Extract attack vector from CVE description"""
        if not text:
            return None
        
        # Check attack vector patterns
        for vector, pattern in self.attack_vector_patterns.items():
            if re.search(pattern, text):
                return vector
        
        # Default to Unknown if not found
        return 'Unknown'
    
    def remove_duplicates(self, df):
        """Remove duplicate data"""
        print("\n" + "="*60)
        print("Step 1: Remove Duplicates")
        print("="*60)
        
        original_count = len(df)
        df = df.drop_duplicates(subset=['cve_id'], keep='first')
        removed_count = original_count - len(df)
        
        print(f"Original record count: {original_count}")
        print(f"Removed duplicates: {removed_count}")
        print(f"Remaining records: {len(df)}")
        
        return df
    
    def handle_missing_values(self, df):
        """Handle missing values"""
        print("\n" + "="*60)
        print("Step 2: Handle Missing Values")
        print("="*60)
        
        # Check missing values
        print("\nMissing value statistics:")
        missing = df.isnull().sum()
        for col, count in missing.items():
            if count > 0:
                print(f"  {col}: {count} ({count/len(df)*100:.1f}%)")
        
        # Remove rows with empty descriptions
        before = len(df)
        df = df[df['description'].notna() & (df['description'] != '')]
        after = len(df)
        if before > after:
            print(f"\n✓ Removed {before-after} records without descriptions")
        
        # Fill other missing values
        df['severity'] = df['severity'].fillna('UNKNOWN')
        df['cvss_score'] = df['cvss_score'].fillna(0.0)
        df['cwe_ids'] = df['cwe_ids'].fillna('Unknown')
        
        print(f"✓ Final valid records: {len(df)}")
        
        return df
    
    def clean_text(self, text):
        """Clean text"""
        if pd.isna(text) or text == '':
            return ''
        
        # Replace URLs with placeholder
        text = re.sub(r'https?://[^\s]+', ' URL ', text)
        
        # Replace emails with placeholder
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', ' EMAIL ', text)
        
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Strip leading/trailing whitespace
        text = text.strip()
        
        return text
    
    def preprocess_enhanced_dataset(self, input_file, output_file):
        """Enhanced preprocessing pipeline with structured field extraction"""
        print("\n" + "="*70)
        print(" "*15 + "Enhanced Data Preprocessing Started")
        print("="*70)
        
        # Read data
        print(f"\nReading: {input_file}")
        df = pd.read_csv(f"data/{input_file}")
        print(f"✓ Read {len(df)} records")
        
        # Step 1: Remove duplicates
        df = self.remove_duplicates(df)
        
        # Step 2: Handle missing values
        df = self.handle_missing_values(df)
        
        # Step 3: Clean text
        print("\n" + "="*60)
        print("Step 3: Clean Text")
        print("="*60)
        
        print("Cleaning description text...")
        df['cleaned_description'] = df['description'].apply(self.clean_text)
        print("✓ Text cleaning complete")
        
        # Step 4: Extract structured fields
        print("\n" + "="*60)
        print("Step 4: Extract Structured Fields (NEW)")
        print("="*60)
        
        print("Extracting software names...")
        df['software_name'] = df['description'].apply(self.extract_software_name)
        print(f"✓ Extracted {df['software_name'].notna().sum()} software names")
        
        print("\nExtracting affected versions...")
        df['affected_versions'] = df['description'].apply(self.extract_affected_versions)
        print(f"✓ Extracted {df['affected_versions'].notna().sum()} version records")
        
        print("\nExtracting vulnerability types...")
        df['vulnerability_type'] = df['description'].apply(self.extract_vulnerability_type)
        print(f"✓ Extracted {df['vulnerability_type'].notna().sum()} vulnerability types")
        
        print("\nExtracting attack vectors...")
        df['attack_vector'] = df['description'].apply(self.extract_attack_vector)
        print(f"✓ Extracted {df['attack_vector'].notna().sum()} attack vectors")
        
        # Show extraction examples
        print("\n" + "="*60)
        print("Extraction Examples")
        print("="*60)
        
        sample_idx = 0
        print(f"\nCVE ID: {df['cve_id'].iloc[sample_idx]}")
        print(f"Description: {df['description'].iloc[sample_idx][:150]}...")
        print(f"\n→ Software Name: {df['software_name'].iloc[sample_idx]}")
        print(f"→ Affected Versions: {df['affected_versions'].iloc[sample_idx]}")
        print(f"→ Vulnerability Type: {df['vulnerability_type'].iloc[sample_idx]}")
        print(f"→ Attack Vector: {df['attack_vector'].iloc[sample_idx]}")
        print(f"→ CVSS Score: {df['cvss_score'].iloc[sample_idx]}")
        print(f"→ Severity: {df['severity'].iloc[sample_idx]}")
        
        # Reorder columns for graph database
        column_order = [
            'cve_id',
            'software_name',
            'affected_versions',
            'vulnerability_type',
            'attack_vector',
            'cvss_score',
            'severity',
            'published_date',
            'cwe_ids',
            'description',
            'cleaned_description'
        ]
        
        df = df[column_order]
        
        # Save
        print("\n" + "="*60)
        print("Saving Enhanced Dataset")
        print("="*60)
        
        output_path = f"data/{output_file}"
        df.to_csv(output_path, index=False, encoding='utf-8-sig')
        print(f"✓ Data saved to: {output_path}")
        
        # Final statistics
        print("\n" + "="*70)
        print(" "*15 + "Enhanced Preprocessing Complete!")
        print("="*70)
        
        print(f"\n📊 Dataset Statistics:")
        print(f"  Total records: {len(df)}")
        print(f"\n  Extracted Fields:")
        print(f"    Software names: {df['software_name'].notna().sum()} ({df['software_name'].notna().sum()/len(df)*100:.1f}%)")
        print(f"    Affected versions: {df['affected_versions'].notna().sum()} ({df['affected_versions'].notna().sum()/len(df)*100:.1f}%)")
        print(f"    Vulnerability types: {df['vulnerability_type'].notna().sum()} ({df['vulnerability_type'].notna().sum()/len(df)*100:.1f}%)")
        print(f"    Attack vectors: {df['attack_vector'].notna().sum()} ({df['attack_vector'].notna().sum()/len(df)*100:.1f}%)")
        
        print(f"\n  Top Software:")
        print(df['software_name'].value_counts().head(5).to_string())
        
        print(f"\n  Vulnerability Type Distribution:")
        print(df['vulnerability_type'].value_counts().to_string())
        
        print(f"\n  Attack Vector Distribution:")
        print(df['attack_vector'].value_counts().to_string())
        
        print(f"\n  Severity Distribution:")
        print(df['severity'].value_counts().to_string())
        
        return df


if __name__ == "__main__":
    print("=" * 70)
    print(" "*10 + "SecurityGraph AI - Enhanced Data Preprocessing")
    print("=" * 70)
    
    preprocessor = EnhancedSecurityPreprocessor()
    
    df = preprocessor.preprocess_enhanced_dataset(
        input_file="raw_cves.csv",
        output_file="enhanced_cves.csv"
    )
    
    print("\n✅ Enhanced preprocessing complete!")
    print("\n📋 Output columns:")
    for i, col in enumerate(df.columns, 1):
        print(f"  {i}. {col}")
    
    print("\n💡 This dataset is ready for Neo4j graph database!")
    print("   Relationships can be built:")
    print("   - (CVE)-[AFFECTS]->(Software)")
    print("   - (CVE)-[HAS_TYPE]->(VulnerabilityType)")
    print("   - (CVE)-[USES_VECTOR]->(AttackVector)")
    print("   - (Software)-[HAS_VERSION]->(Version)")
