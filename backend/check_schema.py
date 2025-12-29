import sys
sys.path.insert(0, 'C:/Projects/NERVE/backend')

from database import CachedASMScan, LightboxScan

print("="*80)
print("DATABASE SCHEMA CHECK")
print("="*80)

print("\nCachedASMScan table columns:")
for col in CachedASMScan.__table__.columns:
    print(f"  {col.name:<25} {col.type}")

print("\nLightboxScan table columns:")
for col in LightboxScan.__table__.columns:
    print(f"  {col.name:<25} {col.type}")