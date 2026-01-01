"""
Business Logic Tests for Lightbox
Tests for IDOR, price manipulation, privilege escalation, and other logic flaws
"""

import requests
from typing import Dict
import concurrent.futures


class BusinessLogicTests:
    def __init__(self, target: str, session: requests.Session):
        self.target = target
        self.session = session

    def run_all_tests(self) -> Dict:
        """Run all business logic tests"""
        tests = [
            self.test_negative_quantities,
            self.test_price_manipulation,
            self.test_idor_access,
            self.test_privilege_escalation,
            self.test_sequential_ids,
            self.test_forced_browsing
        ]

        findings = []
        for test in tests:
            try:
                result = test()
                if result:
                    findings.append(result)
            except Exception as e:
                print(f"[Business Logic] Test error: {e}")

        return {
            'category': 'Business Logic',
            'tests_run': len(tests),
            'findings': findings,
            'status': 'failed' if findings else 'passed'
        }

    def test_negative_quantities(self) -> Dict:
        """Test for negative quantity acceptance"""
        endpoints = ['/api/cart', '/api/order', '/checkout']

        for endpoint in endpoints:
            try:
                url = f"{self.target}{endpoint}"
                payload = {'quantity': -1, 'amount': -100}
                response = self.session.post(url, json=payload, timeout=5)

                if response.status_code in [200, 201]:
                    return {
                        'test': 'Negative Quantity Acceptance',
                        'severity': 'HIGH',
                        'description': 'Application accepts negative quantities',
                        'evidence': f'{endpoint} accepts negative values',
                        'remediation': 'Implement server-side validation for positive values',
                        'cve': 'CWE-20',
                        'cvss': 7.5
                    }
            except:
                continue

        return None

    def test_price_manipulation(self) -> Dict:
        """Test for price manipulation vulnerabilities"""
        endpoints = ['/api/cart', '/api/checkout', '/api/payment']

        for endpoint in endpoints:
            try:
                url = f"{self.target}{endpoint}"
                payload = {'price': 0.01, 'amount': 1, 'total': 0.01}
                response = self.session.post(url, json=payload, timeout=5)

                if response.status_code in [200, 201]:
                    return {
                        'test': 'Price Manipulation',
                        'severity': 'CRITICAL',
                        'description': 'Application may allow client-side price manipulation',
                        'evidence': f'{endpoint} accepts client-supplied prices',
                        'remediation': 'Calculate prices server-side only',
                        'cve': 'CWE-807',
                        'cvss': 9.1
                    }
            except:
                continue

        return None

    def test_idor_access(self) -> Dict:
        """Test for Insecure Direct Object References"""
        test_ids = [1, 2, 100, 999]
        endpoints = ['/api/user', '/api/profile', '/api/account']

        accessible_ids = []

        for endpoint in endpoints:
            for test_id in test_ids:
                try:
                    url = f"{self.target}{endpoint}/{test_id}"
                    response = self.session.get(url, timeout=5)

                    if response.status_code == 200:
                        accessible_ids.append((endpoint, test_id))
                except:
                    continue

        if len(accessible_ids) > 1:
            return {
                'test': 'Insecure Direct Object References (IDOR)',
                'severity': 'HIGH',
                'description': f'Multiple user records accessible via IDs',
                'evidence': f'{len(accessible_ids)} accessible IDs found',
                'remediation': 'Implement authorization checks, use UUIDs',
                'cve': 'CWE-639',
                'cvss': 7.5
            }

        return None

    def test_privilege_escalation(self) -> Dict:
        """Test for accessible admin paths"""
        admin_paths = [
            '/admin', '/administrator', '/admin.php',
            '/api/admin', '/dashboard/admin'
        ]

        accessible_admin = []

        for path in admin_paths:
            try:
                url = f"{self.target}{path}"
                response = self.session.get(url, timeout=5)

                if response.status_code == 200 and 'login' not in response.text.lower():
                    accessible_admin.append(path)
            except:
                continue

        if accessible_admin:
            return {
                'test': 'Accessible Admin Paths',
                'severity': 'MEDIUM',
                'description': 'Admin paths accessible without authentication',
                'evidence': ', '.join(accessible_admin),
                'remediation': 'Implement authentication and authorization',
                'cve': 'CWE-284',
                'cvss': 6.5
            }

        return None

    def test_sequential_ids(self) -> Dict:
        """Test for predictable sequential IDs"""
        endpoints = ['/api/order', '/api/invoice', '/api/ticket']

        for endpoint in endpoints:
            try:
                id1 = f"{self.target}{endpoint}/1"
                id2 = f"{self.target}{endpoint}/2"

                r1 = self.session.get(id1, timeout=5)
                r2 = self.session.get(id2, timeout=5)

                if r1.status_code == 200 and r2.status_code == 200:
                    return {
                        'test': 'Predictable Sequential IDs',
                        'severity': 'LOW',
                        'description': 'Application uses predictable sequential IDs',
                        'evidence': f'{endpoint}/[1,2] both accessible',
                        'remediation': 'Use UUIDs or implement authorization',
                        'cve': 'CWE-330',
                        'cvss': 5.3
                    }
            except:
                continue

        return None

    def test_forced_browsing(self) -> Dict:
        """Test for forced browsing vulnerabilities"""
        restricted_paths = [
            '/backup', '/old', '/test', '/dev',
            '/config', '/internal', '/private'
        ]

        accessible_paths = []

        for path in restricted_paths:
            try:
                url = f"{self.target}{path}"
                response = self.session.get(url, timeout=5)

                if response.status_code == 200:
                    accessible_paths.append(path)
            except:
                continue

        if accessible_paths:
            return {
                'test': 'Forced Browsing',
                'severity': 'MEDIUM',
                'description': 'Restricted paths accessible via direct access',
                'evidence': ', '.join(accessible_paths),
                'remediation': 'Implement access controls on all paths',
                'cve': 'CWE-425',
                'cvss': 5.3
            }

        return None
