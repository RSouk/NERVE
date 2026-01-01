import google.genai as genai
from google.genai import types
import os
import json
from datetime import datetime

# Configure Gemini with new API
client = genai.Client(api_key=os.getenv('GEMINI_API_KEY'))

def generate_vulnerability_report(company: str, xasm_data: dict, lightbox_data: dict) -> dict:
    """
    Generate AI vulnerability assessment report

    Args:
        company: Company domain
        xasm_data: XASM scan results
        lightbox_data: Lightbox scan results

    Returns:
        Comprehensive vulnerability report with risk scoring
    """

    print(f"[AI REPORT] Generating report for {company}")

    # Build comprehensive prompt
    prompt = f"""You are a cybersecurity expert analyzing vulnerability scan results for {company}.

XASM SCAN RESULTS:
{json.dumps(xasm_data, indent=2)}

LIGHTBOX SCAN RESULTS:
{json.dumps(lightbox_data, indent=2)}

Generate a comprehensive vulnerability assessment report in JSON format with the following structure:

{{
    "risk_score": <0-100 integer representing overall risk>,
    "risk_level": "<CRITICAL/HIGH/MEDIUM/LOW>",
    "executive_summary": "<2-3 paragraph non-technical summary for executives>",
    "top_issues": [
        {{
            "title": "<Issue name>",
            "severity": "<CRITICAL/HIGH/MEDIUM/LOW>",
            "cvss": <CVSS score if applicable or null>,
            "cve_cwe": "<CVE/CWE ID if applicable or null>",
            "description": "<Technical description>",
            "impact": "<Business impact>",
            "affected_assets": ["<asset1>", "<asset2>"],
            "remediation": "<Specific remediation steps>",
            "effort_hours": <Estimated hours to fix>,
            "priority": <1-5, 1 being highest>
        }}
    ],
    "attack_scenarios": [
        {{
            "title": "<Scenario name>",
            "steps": ["<step1>", "<step2>", "<step3>"],
            "impact": "<Potential damage>",
            "likelihood": "<HIGH/MEDIUM/LOW>"
        }}
    ],
    "remediation_roadmap": {{
        "immediate": [
            {{
                "task": "<Task description>",
                "effort_hours": <hours>,
                "risk_reduction": <percentage>,
                "priority": <1-5>
            }}
        ],
        "this_week": [...],
        "this_month": [...]
    }},
    "findings_by_category": {{
        "critical": <count>,
        "high": <count>,
        "medium": <count>,
        "low": <count>
    }}
}}

IMPORTANT INSTRUCTIONS:
1. Focus on ACTUAL vulnerabilities found, not theoretical ones
2. Prioritize by REAL business risk, not just CVSS scores
3. Be specific and actionable in remediation steps
4. Consider attack chains (multiple vulns combined)
5. Executive summary should be clear to non-technical readers
6. Limit top_issues to 5 most critical findings
7. Return ONLY valid JSON, no markdown formatting
8. If a vulnerability has no CVE/CWE, use null
9. Ensure all JSON values are properly formatted (numbers as numbers, not strings)
"""

    try:
        # Generate report with new API
        response = client.models.generate_content(
            model='gemini-flash-latest',
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.3,
                max_output_tokens=8000
            )
        )

        # Parse JSON response
        report_text = response.text.strip()

        # Remove markdown code blocks if present
        if report_text.startswith('```'):
            lines = report_text.split('\n')
            report_text = '\n'.join(lines[1:-1])  # Remove first and last line
            if report_text.startswith('json'):
                report_text = report_text[4:].strip()

        report = json.loads(report_text)

        # Add metadata
        report['company'] = company
        report['generated_at'] = datetime.now().isoformat()
        report['scan_data'] = {
            'xasm_date': xasm_data.get('scan_date'),
            'lightbox_date': lightbox_data.get('scan_date'),
            'total_findings': xasm_data.get('total_findings', 0) + lightbox_data.get('total_findings', 0)
        }

        print(f"[AI REPORT] Generated successfully: Risk Score {report['risk_score']}/100")

        return report

    except json.JSONDecodeError as e:
        print(f"[AI REPORT] JSON parsing error: {e}")
        print(f"[AI REPORT] Raw response: {response.text[:500]}")
        raise Exception("Failed to parse AI response as JSON")

    except Exception as e:
        print(f"[AI REPORT] Error generating report: {e}")
        import traceback
        traceback.print_exc()
        raise
