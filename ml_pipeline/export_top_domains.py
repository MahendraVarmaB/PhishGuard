import pandas as pd

df = pd.read_csv('ml_pipeline/data/tranco_43KLX.csv', names=['rank', 'domain'])
domains = df.sort_values('rank').head(50000)['domain']
domains.to_csv('backend/app/top_10k_domains.txt', index=False, header=False)
print(f"Exported {len(domains)} domains")

# Verify virustotal.com is included
vt = df[df['domain'] == 'virustotal.com']
print(f"virustotal.com rank: {vt.iloc[0]['rank']}")
assert 'virustotal.com' in domains.values, "virustotal.com NOT in export!"
print("virustotal.com confirmed in export ✓")
