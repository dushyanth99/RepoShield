"""
Smoke test for the updated StaticScannerInterface.
Tests both scan() (inline) and scan_github_repo() surfaces.
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.scanner import StaticScannerInterface


async def main():
    scanner = StaticScannerInterface()

    # ── Test 1: Inline scan — hardcoded secret ────────────────────────────
    print("=" * 60)
    print("TEST 1: Inline scan — hardcoded secret detection")
    print("=" * 60)
    vuln_code = '''
api_key = "sk-live-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
db_pass = "SuperSecret123!"
clean_var = "hello world"
'''
    result = await scanner.scan("test_file.py", vuln_code)
    print(f"  Total findings : {result['total_findings']}")
    print(f"  Has critical   : {result['has_critical']}")
    for f in result["findings"]:
        print(f"  - {f['category']} at line {f['location']['line_number']}: {f['message']}")
    assert result["total_findings"] >= 2, "Expected at least 2 hardcoded secret findings"
    print("  [PASS] PASSED\n")

    # ── Test 2: Inline scan — SQL injection ───────────────────────────────
    print("=" * 60)
    print("TEST 2: Inline scan — SQL injection detection")
    print("=" * 60)
    sqli_code = '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
'''
    result2 = await scanner.scan("db_helper.py", sqli_code)
    print(f"  Total findings : {result2['total_findings']}")
    print(f"  Has critical   : {result2['has_critical']}")
    for f in result2["findings"]:
        print(f"  - {f['category']} at line {f['location']['line_number']}: {f['message']}")
    assert result2["total_findings"] >= 1, "Expected at least 1 SQL injection finding"
    print("  [PASS] PASSED\n")

    # ── Test 3: Inline scan — clean code ──────────────────────────────────
    print("=" * 60)
    print("TEST 3: Inline scan — clean code (no findings)")
    print("=" * 60)
    clean_code = '''
import os

def get_config():
    return os.environ.get("API_KEY")
'''
    result3 = await scanner.scan("clean.py", clean_code)
    print(f"  Total findings : {result3['total_findings']}")
    assert result3["total_findings"] == 0, "Expected 0 findings for clean code"
    print("  [PASS] PASSED\n")

    # ── Test 4: scan_github_repo — real clone ─────────────────────────────
    print("=" * 60)
    print("TEST 4: scan_github_repo — shallow clone + walk")
    print("=" * 60)
    # Use a small known-vulnerable test repo (public)
    repo_result = await scanner.scan_github_repo(
        "https://github.com/OWASP/Vulnerable-Web-Application.git"
    )
    print(f"  Status         : {repo_result['status']}")
    if repo_result["status"] == "vulnerable":
        print(f"  File path      : {repo_result['file_path']}")
        print(f"  Category       : {repo_result['category']}")
        print(f"  Business impact: {repo_result['business_impact']}")
        print(f"  Code preview   : {repo_result['raw_code'][:120]}...")
    elif repo_result["status"] == "secure":
        print("  No vulnerabilities detected in repository.")
    else:
        print(f"  Error: {repo_result.get('message', 'unknown')}")
    print("  [DONE] COMPLETED\n")

    print("All smoke tests passed.")


if __name__ == "__main__":
    asyncio.run(main())
