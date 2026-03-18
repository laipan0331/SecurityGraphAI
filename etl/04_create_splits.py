import pandas as pd
from sklearn.model_selection import train_test_split

print("="*70)
print(" "*20 + "Dataset Split")
print("="*70)

print("\nReading data...")
df = pd.read_csv('data/processed_cves.csv')
print(f"✓ Read {len(df)} records\n")

# Check severity distribution
print("Severity Distribution:")
print("-"*70)
for severity, count in df['severity'].value_counts().items():
    print(f"  {severity:10s}: {count:3d} ({count/len(df)*100:5.1f}%)")
print()

low_df = df[df['severity'] == 'LOW']
other_df = df[df['severity'] != 'LOW']

print(f"Note: LOW severity has {len(low_df)} records, will be placed in training set")
print()

print(f"LOW records: {len(low_df)} records")
print(f"Other records: {len(other_df)} records\n")

# Perform stratified split on other data
print("Splitting data...")
train_val, test = train_test_split(
    other_df, 
    test_size=0.15, 
    random_state=42, 
    stratify=other_df['severity']
)

train, val = train_test_split(
    train_val, 
    test_size=0.176, 
    random_state=42, 
    stratify=train_val['severity']
)

# Add LOW records to training set
train = pd.concat([train, low_df], ignore_index=True)

print(f"\nTraining set: {len(train)} records ({len(train)/len(df)*100:.1f}%)")
print(f"Validation set: {len(val)} records ({len(val)/len(df)*100:.1f}%)")
print(f"Test set: {len(test)} records ({len(test)/len(df)*100:.1f}%)\n")

# Display severity distribution for each set
print("="*70)
print("Severity Distribution Across Datasets")
print("="*70)
print()

print(f"{'Severity':<12} {'Train':<15} {'Validation':<15} {'Test':<15}")
print("-"*70)

for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
    if severity in df['severity'].values:
        train_count = (train['severity'] == severity).sum()
        val_count = (val['severity'] == severity).sum()
        test_count = (test['severity'] == severity).sum()
        
        train_pct = train_count / len(train) * 100
        val_pct = val_count / len(val) * 100 if len(val) > 0 else 0
        test_pct = test_count / len(test) * 100 if len(test) > 0 else 0
        
        print(f"{severity:<12} {train_count:3d} ({train_pct:5.1f}%)  "
              f"{val_count:3d} ({val_pct:5.1f}%)  "
              f"{test_count:3d} ({test_pct:5.1f}%)")
print()

# Save files
print("="*70)
print("Saving Datasets")
print("="*70)
print()

train.to_csv('data/train.csv', index=False, encoding='utf-8-sig')
print("✓ Training set saved to: data/train.csv")

val.to_csv('data/val.csv', index=False, encoding='utf-8-sig')
print("✓ Validation set saved to: data/val.csv")

test.to_csv('data/test.csv', index=False, encoding='utf-8-sig')
print("✓ Test set saved to: data/test.csv")

print()
print("="*70)
print("✓ Data split complete!")
print("="*70)
print()
print("🎉 Congratulations! All data preprocessing steps completed!")
print()
print("You now have:")
print("  ✓ data/raw_cves.csv           - Raw CVE data (97 records)")
print("  ✓ data/processed_cves.csv     - Cleaned data (97 records)")
print("  ✓ data/train.csv              - Training set")
print("  ✓ data/val.csv                - Validation set")
print("  ✓ data/test.csv               - Test set")
print("  ✓ data/statistics_report.txt  - Statistics report")
print("  ✓ data/statistics_visualizations.png - Data visualizations")
print()
print("📊 Assignment Progress:")
print("  ✅ 1. Dataset selection: Complete")
print("  ✅ 2. Data cleaning and preprocessing: Complete")
print("  ✅ 3. Data statistics report: Complete")
print("  ✅ 4. Data splitting: Complete")