from api_breaches import check_leakcheck_api, check_breachdirectory_api, check_all_apis
from dotenv import load_dotenv

load_dotenv()

print("=" * 60)
print("GHOST - Breach Source Testing")
print("=" * 60)

# Test emails - mix of known breached and clean
test_emails = [
    "test@adobe.com",           # Likely in Adobe breach
    "test@linkedin.com",        # Likely in LinkedIn breach  
    "eceer.soukoroff832@@gmail.com", # Replace with your actual email
    "notfound@example.com",     # Should return 0 results
]

print("\n📧 Testing individual sources:\n")

for email in test_emails:
    print(f"\n--- Testing: {email} ---")
    
    # Test LeakCheck
    print("\n1. LeakCheck:")
    lc_breaches, lc_count = check_leakcheck_api(email)
    if lc_count >= 0:
        print(f"   ✓ Found {lc_count} breaches")
        if lc_count > 0:
            for b in lc_breaches[:3]:
                print(f"     - {b['name']}")
    else:
        print(f"   ✗ Error code: {lc_count}")
    
    # Test BreachDirectory
    print("\n2. BreachDirectory:")
    bd_breaches, bd_count = check_breachdirectory_api(email)
    if bd_count >= 0:
        print(f"   ✓ Found {bd_count} breaches")
        if bd_count > 0:
            for b in bd_breaches[:3]:
                print(f"     - {b['name']}")
    else:
        print(f"   ✗ Error code: {bd_count}")
    
    print("\n" + "-" * 60)

print("\n\n🔄 Testing combined API check:\n")

for email in test_emails[:2]:  # Test first 2 with combined
    print(f"\nCombined check: {email}")
    breaches, count, sources = check_all_apis(email)
    print(f"Result: {count} breaches from {sources}")
    
print("\n" + "=" * 60)
print("Testing complete!")
print("=" * 60)