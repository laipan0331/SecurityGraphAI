"""
SecurityGraph AI - Step 2: Data Preprocessing
Clean and standardize CVE data
"""

import pandas as pd
import re
import nltk
from nltk.tokenize import word_tokenize, sent_tokenize
from nltk.corpus import stopwords
import string

class SecurityTextPreprocessor:
    def __init__(self):
        self.stop_words = set(stopwords.words('english'))
        
        # 安全相关的正则表达式
        self.security_patterns = {
            'cve_id': r'CVE-\d{4}-\d{4,7}',
            'cwe_id': r'CWE-\d+',
            'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'version': r'v?\d+\.\d+\.?\d*',
            'url': r'https?://[^\s]+',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        }
    
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
        
        # 替换URL
        text = re.sub(self.security_patterns['url'], ' URL ', text)
        
        # 替换Email
        text = re.sub(self.security_patterns['email'], ' EMAIL ', text)
        
        # 移除HTML标签
        text = re.sub(r'<[^>]+>', '', text)
        
        # 移除多余空格
        text = re.sub(r'\s+', ' ', text)
        
        # 移除首尾空格
        text = text.strip()
        
        return text
    
    def extract_security_entities(self, text):
        """Extract security entities"""
        entities = {}
        
        for entity_type in ['cve_id', 'cwe_id', 'ip_address', 'version']:
            pattern = self.security_patterns[entity_type]
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                entities[entity_type] = list(dict.fromkeys(matches))
        
        return entities
    
    def tokenize_text(self, text):
        """Tokenize text"""
        if not text or text == '':
            return []
        
        tokens = word_tokenize(text.lower())
        tokens = [token for token in tokens if token not in string.punctuation]
        tokens = [token for token in tokens if len(token) > 1 or token in ['c', 'r']]
        
        return tokens
    
    def preprocess_dataset(self, input_file, output_file):
        """Complete preprocessing pipeline"""
        print("\n" + "="*70)
        print(" "*20 + "Data Preprocessing Started")
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
        
        # Show comparison
        print("\n【Before/After Cleaning Example】")
        print("-" * 70)
        sample_idx = 0
        print("Original text:")
        print(df['description'].iloc[sample_idx][:150] + "...")
        print("\nCleaned text:")
        print(df['cleaned_description'].iloc[sample_idx][:150] + "...")
        print("-" * 70)
        
        # Step 4: Extract entities
        print("\n" + "="*60)
        print("Step 4: Extract Security Entities")
        print("="*60)
        
        print("Extracting CVE IDs, CWE IDs, version numbers, etc...")
        df['extracted_entities'] = df['description'].apply(self.extract_security_entities)
        print("✓ Entity extraction complete")
        
        # Step 5: Tokenization
        print("\n" + "="*60)
        print("Step 5: Tokenization")
        print("="*60)
        
        print("Tokenizing text...")
        df['tokens'] = df['cleaned_description'].apply(self.tokenize_text)
        df['token_count'] = df['tokens'].apply(len)
        print("✓ Tokenization complete")
        
        # Show tokenization example
        print("\n【Tokenization Example】")
        print("-" * 70)
        print("Original:", df['cleaned_description'].iloc[sample_idx][:100])
        print("\nFirst 20 tokens:", df['tokens'].iloc[sample_idx][:20])
        print("-" * 70)
        
        # Step 6: Sentence splitting
        print("\n" + "="*60)
        print("Step 6: Sentence Splitting")
        print("="*60)
        
        print("Splitting sentences...")
        df['sentences'] = df['cleaned_description'].apply(sent_tokenize)
        df['sentence_count'] = df['sentences'].apply(len)
        print("✓ Sentence splitting complete")
        
        # Save
        print("\n" + "="*60)
        print("Saving Processed Data")
        print("="*60)
        
        output_path = f"data/{output_file}"
        df.to_csv(output_path, index=False, encoding='utf-8-sig')
        print(f"✓ Data saved to: {output_path}")
        
        # Final statistics
        print("\n" + "="*70)
        print(" "*20 + "Preprocessing Complete!")
        print("="*70)
        print(f"\nFinal dataset statistics:")
        print(f"  Total records: {len(df)}")
        print(f"  Average token count: {df['token_count'].mean():.2f}")
        print(f"  Average sentence count: {df['sentence_count'].mean():.2f}")
        print(f"\n  Severity distribution:")
        for severity, count in df['severity'].value_counts().items():
            print(f"    {severity}: {count} ({count/len(df)*100:.1f}%)")
        
        return df


if __name__ == "__main__":
    print("=" * 70)
    print(" "*15 + "SecurityGraph AI - Data Preprocessing")
    print("=" * 70)
    
    preprocessor = SecurityTextPreprocessor()
    
    df = preprocessor.preprocess_dataset(
        input_file="raw_cves.csv",
        output_file="processed_cves.csv"
    )
    
    print("\n✓ Step 2 Complete!")
    print("\nNext step: Run python etl/03_generate_statistics.py to generate statistics report")