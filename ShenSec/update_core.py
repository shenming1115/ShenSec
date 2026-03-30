import re
import sys

with open('ShenSec/src/shensec/scanner/core.py', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Update X-Powered-By severity
text = text.replace('severity=Severity.LOW,', 'severity=Severity.INFO,', 1)

# 2. Update CORS severity and description
text = text.replace('Rule: Overly Permissive CORS Policy', 'Rule: Permissive CORS Policy')
text = text.replace('title="Overly Permissive CORS Policy"', 'title="Permissive CORS Policy"')
text = text.replace('severity=Severity.MEDIUM,', 'severity=Severity.LOW,', 1)
text = text.replace('description="Access-Control-Allow-Origin is set to \'*\'', 'description="Access-Control-Allow-Origin is set to \'*\'') # It's multi-line maybe? Let's just regex
text = re.sub(r'description="Access-Control-Allow-Origin is set to \'\*\'. Any website can read data from this endpoint."', r'description="Access-Control-Allow-Origin is set to \'\*\'. Assess if this endpoint handles sensitive user session data."', text)
text = re.sub(r'recommendation="Restrict CORS to specific trusted domains."', r'recommendation="If this is an authenticated API, restrict CORS to specific trusted domains."', text)

# 3. Add response_time_ms to analyze_response
text = text.replace('status_code=response.status_code,\n        findings=all_findings', 'status_code=response.status_code,\n        response_time_ms=0.0,\n        findings=all_findings')
text = text.replace('status_code=response.status_code,\r\n        findings=all_findings', 'status_code=response.status_code,\r\n        response_time_ms=0.0,\r\n        findings=all_findings')

# 4. Aggregation logic
agg_logic = """
    counts = {s.value: 0 for s in Severity}
    for f in scan_result.findings:
        counts[f.severity.value] += 1
        
    rating = Severity.INFO
    if counts[Severity.CRITICAL.value] > 0:
        rating = Severity.CRITICAL
    elif counts[Severity.HIGH.value] > 0:
        rating = Severity.HIGH
    elif counts[Severity.MEDIUM.value] > 0:
        rating = Severity.MEDIUM
    elif counts[Severity.LOW.value] > 0:
        rating = Severity.LOW

    scan_result.severity_counts = counts
    scan_result.risk_rating = rating
    scan_result.response_time_ms = round((time.time() - start_time) * 1000, 2)
    return scan_result
"""

text = re.sub(r'    scan_result\.response_time_ms = round.*?\n    return scan_result', agg_logic.lstrip('\n'), text, flags=re.DOTALL)

# Default to "active scan" in docstring instead of "deep scan"
text = text.replace('Perform a deep scan including an active OPTIONS request test.', 'Perform an active scan (Probing HTTP Methods, WAF heuristic, Framework exposure).')

with open('ShenSec/src/shensec/scanner/core.py', 'w', encoding='utf-8') as f:
    f.write(text)

print("Updated core.py")
