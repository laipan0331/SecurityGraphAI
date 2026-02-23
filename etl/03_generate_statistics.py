"""
SecurityGraph AI - Step 3: Data Statistics Report
Generate detailed data analysis reports and visualizations
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter
import json

# Set Chinese font (if needed)
plt.rcParams['font.sans-serif'] = ['Microsoft YaHei', 'SimHei', 'Arial']
plt.rcParams['axes.unicode_minus'] = False

class SecurityDataStatistics:
    def __init__(self, df):
        self.df = df
    
    def generate_report(self):
        """Generate text statistics report"""
        report = []
        report.append("=" * 80)
        report.append("SECURITYGRAPH AI - DATA STATISTICS REPORT")
        report.append("=" * 80)
        report.append("")
        
        # 1. Dataset Overview
        report.append("1. Dataset Overview")
        report.append("-" * 80)
        report.append(f"   Total CVE count: {len(self.df)}")
        
        # Date range
        self.df['published_date'] = pd.to_datetime(self.df['published_date'])
        date_min = self.df['published_date'].min().strftime('%Y-%m-%d')
        date_max = self.df['published_date'].max().strftime('%Y-%m-%d')
        report.append(f"   Time range: {date_min} to {date_max}")
        report.append("")
        
        # 2. Text Statistics
        report.append("2. Text Feature Statistics")
        report.append("-" * 80)
        report.append(f"   Average description length: {self.df['cleaned_description'].str.len().mean():.2f} characters")
        report.append(f"   Longest description: {self.df['cleaned_description'].str.len().max()} characters")
        report.append(f"   Shortest description: {self.df['cleaned_description'].str.len().min()} characters")
        report.append(f"   Average token count: {self.df['token_count'].mean():.2f}")
        report.append(f"   Average sentence count: {self.df['sentence_count'].mean():.2f}")
        report.append("")
        
        # 3. Severity Distribution
        report.append("3. Severity Distribution")
        report.append("-" * 80)
        severity_counts = self.df['severity'].value_counts()
        for severity, count in severity_counts.items():
            percentage = count / len(self.df) * 100
            bar = "█" * int(percentage / 2)  # 简单的条形图
            report.append(f"   {severity:10s}: {count:3d} ({percentage:5.1f}%) {bar}")
        report.append("")
        
        # 4. CVSS Score Statistics
        report.append("4. CVSS Score Statistics")
        report.append("-" * 80)
        cvss_data = self.df[self.df['cvss_score'] > 0]['cvss_score']
        report.append(f"   Average CVSS: {cvss_data.mean():.2f}")
        report.append(f"   Median CVSS: {cvss_data.median():.2f}")
        report.append(f"   Highest CVSS: {cvss_data.max():.2f}")
        report.append(f"   Lowest CVSS: {cvss_data.min():.2f}")
        report.append("")
        
        # CVSS score range distribution
        report.append("   CVSS score range distribution:")
        critical = (cvss_data >= 9.0).sum()
        high = ((cvss_data >= 7.0) & (cvss_data < 9.0)).sum()
        medium = ((cvss_data >= 4.0) & (cvss_data < 7.0)).sum()
        low = (cvss_data < 4.0).sum()
        
        report.append(f"     9.0-10.0 (Critical): {critical}")
        report.append(f"     7.0-8.9  (High):     {high}")
        report.append(f"     4.0-6.9  (Medium):   {medium}")
        report.append(f"     0.0-3.9  (Low):      {low}")
        report.append("")
        
        # 5. Vocabulary Statistics
        report.append("5. Vocabulary Statistics")
        report.append("-" * 80)
        all_tokens = []
        for tokens in self.df['tokens']:
            if isinstance(tokens, list):
                all_tokens.extend(tokens)
        
        vocab = set(all_tokens)
        report.append(f"   Total token count: {len(all_tokens)}")
        report.append(f"   Unique token count (vocabulary size): {len(vocab)}")
        report.append(f"   Vocabulary richness: {len(vocab)/len(all_tokens):.4f}")
        report.append("")
        
        # 6. Most Common Security Terms
        report.append("6. Most Common Security Terms (Top 30)")
        report.append("-" * 80)
        word_freq = Counter(all_tokens)
        
        # 过滤常见停用词
        common_words = ['the', 'a', 'an', 'in', 'to', 'of', 'and', 'or', 'for', 
                       'via', 'with', 'from', 'allows', 'allow', 'could', 'may']
        
        security_terms = [(word, count) for word, count in word_freq.most_common(100) 
                         if word not in common_words and len(word) > 2][:30]
        
        for i, (word, count) in enumerate(security_terms, 1):
            report.append(f"   {i:2d}. {word:20s}: {count:4d}")
        report.append("")
        
        # 7. CWE Statistics
        report.append("7. CWE (Vulnerability Type) Statistics")
        report.append("-" * 80)
        cwe_count = self.df['cwe_ids'].notna().sum()
        report.append(f"   CVEs with CWE labels: {cwe_count} ({cwe_count/len(self.df)*100:.1f}%)")
        report.append(f"   CVEs without CWE labels: {len(self.df)-cwe_count} ({(len(self.df)-cwe_count)/len(self.df)*100:.1f}%)")
        
        # Extract all CWE IDs
        all_cwes = []
        for cwe in self.df['cwe_ids'].dropna():
            if isinstance(cwe, str) and cwe != 'Unknown':
                all_cwes.extend([c.strip() for c in cwe.split(',')])
        
        if all_cwes:
            cwe_freq = Counter(all_cwes)
            report.append(f"\n   Most common CWE types:")
            for cwe, count in cwe_freq.most_common(10):
                report.append(f"     {cwe}: {count}")
        report.append("")
        
        # 8. Year Distribution
        report.append("8. CVE Publication Year Distribution")
        report.append("-" * 80)
        self.df['year'] = self.df['published_date'].dt.year
        year_counts = self.df['year'].value_counts().sort_index()
        for year, count in year_counts.items():
            report.append(f"   {int(year)}: {count} CVEs")
        report.append("")
        
        report.append("=" * 80)
        report.append("Report Generation Complete")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def create_visualizations(self):
        """Create visualization charts"""
        fig = plt.figure(figsize=(16, 12))
        
        # 1. Severity Distribution (Pie Chart)
        ax1 = plt.subplot(3, 3, 1)
        severity_counts = self.df['severity'].value_counts()
        colors = {'CRITICAL': '#d32f2f', 'HIGH': '#f57c00', 
                 'MEDIUM': '#fbc02d', 'LOW': '#7cb342', 'UNKNOWN': '#9e9e9e'}
        pie_colors = [colors.get(s, '#9e9e9e') for s in severity_counts.index]
        ax1.pie(severity_counts.values, labels=severity_counts.index, autopct='%1.1f%%',
                colors=pie_colors, startangle=90)
        ax1.set_title('Severity Distribution', fontsize=12, fontweight='bold')
        
        # 2. CVSS Score Distribution (Histogram)
        ax2 = plt.subplot(3, 3, 2)
        cvss_data = self.df[self.df['cvss_score'] > 0]['cvss_score']
        ax2.hist(cvss_data, bins=20, edgecolor='black', color='steelblue', alpha=0.7)
        ax2.set_title('CVSS Score Distribution', fontsize=12, fontweight='bold')
        ax2.set_xlabel('CVSS Score')
        ax2.set_ylabel('Frequency')
        ax2.grid(alpha=0.3)
        ax2.axvline(cvss_data.mean(), color='red', linestyle='--', 
                   label=f'Mean: {cvss_data.mean():.2f}')
        ax2.legend()
        
        # 3. Description Length Distribution
        ax3 = plt.subplot(3, 3, 3)
        desc_lengths = self.df['cleaned_description'].str.len()
        ax3.hist(desc_lengths, bins=30, edgecolor='black', color='coral', alpha=0.7)
        ax3.set_title('Description Length Distribution', fontsize=12, fontweight='bold')
        ax3.set_xlabel('Characters')
        ax3.set_ylabel('Frequency')
        ax3.grid(alpha=0.3)
        
        # 4. Token Count Distribution
        ax4 = plt.subplot(3, 3, 4)
        ax4.hist(self.df['token_count'], bins=30, edgecolor='black', 
                color='lightgreen', alpha=0.7)
        ax4.set_title('Token Count Distribution', fontsize=12, fontweight='bold')
        ax4.set_xlabel('Tokens')
        ax4.set_ylabel('Frequency')
        ax4.grid(alpha=0.3)
        
        # 5. Year Distribution (Bar Chart)
        ax5 = plt.subplot(3, 3, 5)
        self.df['year'] = self.df['published_date'].dt.year
        year_counts = self.df['year'].value_counts().sort_index()
        ax5.bar(year_counts.index, year_counts.values, color='skyblue', edgecolor='black')
        ax5.set_title('CVE Count by Year', fontsize=12, fontweight='bold')
        ax5.set_xlabel('Year')
        ax5.set_ylabel('Count')
        ax5.tick_params(axis='x', rotation=45)
        ax5.grid(alpha=0.3)
        
        # 6. Top 15 Most Common Words (Horizontal Bar Chart)
        ax6 = plt.subplot(3, 3, 6)
        all_tokens = []
        for tokens in self.df['tokens']:
            if isinstance(tokens, list):
                all_tokens.extend(tokens)
        
        word_freq = Counter(all_tokens)
        common_words = ['the', 'a', 'an', 'in', 'to', 'of', 'and', 'or', 'for', 
                       'via', 'with', 'from', 'allows', 'allow', 'could', 'may']
        security_terms = [(word, count) for word, count in word_freq.most_common(100) 
                         if word not in common_words and len(word) > 2][:15]
        
        words, counts = zip(*security_terms)
        ax6.barh(range(len(words)), counts, color='mediumpurple')
        ax6.set_yticks(range(len(words)))
        ax6.set_yticklabels(words)
        ax6.set_title('Top 15 Security Terms', fontsize=12, fontweight='bold')
        ax6.set_xlabel('Frequency')
        ax6.invert_yaxis()
        ax6.grid(alpha=0.3, axis='x')
        
        # 7. CVSS vs Description Length (Scatter Plot)
        ax7 = plt.subplot(3, 3, 7)
        scatter_data = self.df[self.df['cvss_score'] > 0]
        ax7.scatter(scatter_data['cvss_score'], 
                   scatter_data['cleaned_description'].str.len(),
                   alpha=0.5, color='teal')
        ax7.set_title('CVSS Score vs Description Length', fontsize=12, fontweight='bold')
        ax7.set_xlabel('CVSS Score')
        ax7.set_ylabel('Description Length')
        ax7.grid(alpha=0.3)
        
        # 8. Severity vs Year (Stacked Bar Chart)
        ax8 = plt.subplot(3, 3, 8)
        severity_by_year = pd.crosstab(self.df['year'], self.df['severity'])
        severity_by_year.plot(kind='bar', stacked=True, ax=ax8, 
                             color=[colors.get(s, '#9e9e9e') for s in severity_by_year.columns])
        ax8.set_title('Severity Distribution by Year', fontsize=12, fontweight='bold')
        ax8.set_xlabel('Year')
        ax8.set_ylabel('Count')
        ax8.tick_params(axis='x', rotation=45)
        ax8.legend(title='Severity', bbox_to_anchor=(1.05, 1), loc='upper left')
        ax8.grid(alpha=0.3)
        
        # 9. Sentence Count Distribution
        ax9 = plt.subplot(3, 3, 9)
        ax9.hist(self.df['sentence_count'], bins=range(1, int(self.df['sentence_count'].max())+2),
                edgecolor='black', color='salmon', alpha=0.7)
        ax9.set_title('Sentence Count Distribution', fontsize=12, fontweight='bold')
        ax9.set_xlabel('Sentences')
        ax9.set_ylabel('Frequency')
        ax9.grid(alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('data/statistics_visualizations.png', dpi=300, bbox_inches='tight')
        print("✓ Visualization charts saved to: data/statistics_visualizations.png")
        plt.show()


if __name__ == "__main__":
    print("=" * 70)
    print(" "*15 + "SecurityGraph AI - Data Statistics")
    print("=" * 70)
    print()
    
    # Read processed data
    print("Reading processed data...")
    df = pd.read_csv("data/processed_cves.csv")
    
    # Parse tokens column (convert from string back to list)
    import ast
    df['tokens'] = df['tokens'].apply(lambda x: ast.literal_eval(x) if isinstance(x, str) else [])
    df['sentences'] = df['sentences'].apply(lambda x: ast.literal_eval(x) if isinstance(x, str) else [])
    
    print(f"✓ Read {len(df)} records\n")
    
    # Generate statistics report
    stats = SecurityDataStatistics(df)
    
    print("Generating statistics report...")
    report = stats.generate_report()
    
    # Save report
    with open('data/statistics_report.txt', 'w', encoding='utf-8') as f:
        f.write(report)
    
    print("\n✓ Statistics report saved to: data/statistics_report.txt\n")
    
    # Display report
    print(report)
    
    # Generate visualizations
    print("\nGenerating visualization charts...")
    stats.create_visualizations()
    
    print("\n" + "=" * 70)
    print("✓ Step 3 Complete!")
    print("=" * 70)
    print("\nNext step: Run python etl/04_create_splits.py to split the dataset")