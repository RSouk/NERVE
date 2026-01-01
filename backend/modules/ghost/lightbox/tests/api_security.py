"""
API Security Tests for Lightbox
Tests for GraphQL, REST API, Swagger exposure, authentication, and more
"""

import requests
from typing import Dict, List
import json


class APISecurityTests:
    def __init__(self, target: str, session: requests.Session):
        self.target = target
        self.session = session
        self.results = []

    def run_all_tests(self) -> Dict:
        """Run all API security tests"""
        tests = [
            self.test_graphql_introspection,
            self.test_rest_api_enumeration,
            self.test_api_versioning,
            self.test_swagger_exposure,
            self.test_api_authentication,
            self.test_mass_assignment,
            self.test_api_rate_limiting,
            self.test_options_method,
            self.test_verbose_errors,
            self.test_api_documentation_exposure
        ]

        findings = []
        for test in tests:
            try:
                result = test()
                if result:
                    findings.append(result)
            except Exception as e:
                print(f"[API Security] Test error: {e}")

        return {
            'category': 'API Security',
            'tests_run': len(tests),
            'findings': findings,
            'status': 'failed' if findings else 'passed'
        }

    def test_graphql_introspection(self) -> Dict:
        """Test if GraphQL introspection is enabled"""
        graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql', '/query']

        introspection_query = {
            "query": "{ __schema { queryType { name } } }"
        }

        for path in graphql_paths:
            try:
                url = f"{self.target}{path}"
                response = self.session.post(url, json=introspection_query, timeout=5)

                if response.status_code == 200 and '__schema' in response.text:
                    return {
                        'test': 'GraphQL Introspection Enabled',
                        'severity': 'MEDIUM',
                        'description': f'GraphQL introspection is enabled at {path}',
                        'evidence': url,
                        'remediation': 'Disable introspection in production environments',
                        'cve': None,
                        'cvss': 5.3
                    }
            except:
                continue

        return None

    def test_rest_api_enumeration(self) -> Dict:
        """Test for API endpoint enumeration"""
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/v1', '/v2',
            '/rest', '/rest/v1', '/api/users', '/api/admin'
        ]

        exposed_endpoints = []

        for path in api_paths:
            try:
                url = f"{self.target}{path}"
                response = self.session.get(url, timeout=5)

                if response.status_code in [200, 401, 403]:
                    content_type = response.headers.get('Content-Type', '')
                    if 'json' in content_type or 'api' in response.text.lower():
                        exposed_endpoints.append({
                            'path': path,
                            'status': response.status_code,
                            'type': content_type
                        })
            except:
                continue

        if exposed_endpoints:
            return {
                'test': 'API Endpoint Enumeration',
                'severity': 'INFO',
                'description': f'Found {len(exposed_endpoints)} API endpoints',
                'evidence': ', '.join([e['path'] for e in exposed_endpoints]),
                'remediation': 'Implement proper API authentication and access controls',
                'cve': None,
                'cvss': 0
            }

        return None

    def test_api_versioning(self) -> Dict:
        """Test for old API versions still accessible"""
        versions = ['v1', 'v2', 'v3', '1', '2', '3']
        accessible_versions = []

        for version in versions:
            try:
                url = f"{self.target}/api/{version}"
                response = self.session.get(url, timeout=5)

                if response.status_code in [200, 401, 403]:
                    accessible_versions.append(version)
            except:
                continue

        if len(accessible_versions) > 1:
            return {
                'test': 'Multiple API Versions Accessible',
                'severity': 'LOW',
                'description': f'Multiple API versions accessible: {", ".join(accessible_versions)}',
                'evidence': f"{self.target}/api/[{', '.join(accessible_versions)}]",
                'remediation': 'Deprecate and disable old API versions',
                'cve': None,
                'cvss': 3.1
            }

        return None

    def test_swagger_exposure(self) -> Dict:
        """Test for exposed Swagger/OpenAPI documentation"""
        swagger_paths = [
            '/swagger', '/swagger-ui', '/swagger-ui.html',
            '/api-docs', '/api/docs', '/docs',
            '/openapi.json', '/swagger.json',
            '/v2/api-docs', '/v3/api-docs'
        ]

        for path in swagger_paths:
            try:
                url = f"{self.target}{path}"
                response = self.session.get(url, timeout=5)

                if response.status_code == 200 and ('swagger' in response.text.lower() or 'openapi' in response.text.lower()):
                    return {
                        'test': 'API Documentation Exposed',
                        'severity': 'MEDIUM',
                        'description': f'API documentation exposed at {path}',
                        'evidence': url,
                        'remediation': 'Restrict access to API documentation in production',
                        'cve': None,
                        'cvss': 5.3
                    }
            except:
                continue

        return None

    def test_api_authentication(self) -> Dict:
        """Test API authentication requirements"""
        api_endpoints = ['/api/users', '/api/admin', '/api/config', '/api/data']

        unauthenticated_access = []

        for endpoint in api_endpoints:
            try:
                url = f"{self.target}{endpoint}"
                response = self.session.get(url, timeout=5)

                if response.status_code == 200:
                    unauthenticated_access.append(endpoint)
            except:
                continue

        if unauthenticated_access:
            return {
                'test': 'API Endpoints Without Authentication',
                'severity': 'HIGH',
                'description': f'API endpoints accessible without authentication',
                'evidence': ', '.join(unauthenticated_access),
                'remediation': 'Implement authentication on all sensitive API endpoints',
                'cve': None,
                'cvss': 7.5
            }

        return None

    def test_mass_assignment(self) -> Dict:
        """Test for mass assignment vulnerability"""
        test_endpoints = ['/api/users', '/api/profile', '/api/user']

        for endpoint in test_endpoints:
            try:
                url = f"{self.target}{endpoint}"

                malicious_data = {
                    'username': 'test',
                    'email': 'test@test.com',
                    'role': 'admin',
                    'isAdmin': True
                }

                response = self.session.post(url, json=malicious_data, timeout=5)

                if response.status_code in [200, 201]:
                    return {
                        'test': 'Potential Mass Assignment',
                        'severity': 'MEDIUM',
                        'description': 'API may be vulnerable to mass assignment attacks',
                        'evidence': f'{endpoint} accepts privileged fields',
                        'remediation': 'Use allowlist for accepted fields',
                        'cve': 'CWE-915',
                        'cvss': 6.5
                    }
            except:
                continue

        return None

    def test_api_rate_limiting(self) -> Dict:
        """Test for API rate limiting"""
        test_url = f"{self.target}/api"

        try:
            responses = []
            for i in range(20):
                response = self.session.get(test_url, timeout=2)
                responses.append(response.status_code)

            if 429 not in responses:
                return {
                    'test': 'No API Rate Limiting',
                    'severity': 'MEDIUM',
                    'description': 'API does not implement rate limiting',
                    'evidence': '20 rapid requests completed without throttling',
                    'remediation': 'Implement rate limiting to prevent abuse',
                    'cve': 'CWE-770',
                    'cvss': 5.3
                }
        except:
            pass

        return None

    def test_options_method(self) -> Dict:
        """Test for excessive OPTIONS method disclosure"""
        try:
            response = self.session.options(self.target, timeout=5)

            if response.status_code == 200:
                allow_header = response.headers.get('Allow', '')

                dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
                found_dangerous = [m for m in dangerous_methods if m in allow_header]

                if found_dangerous:
                    return {
                        'test': 'Excessive HTTP Methods Allowed',
                        'severity': 'LOW',
                        'description': f'Dangerous HTTP methods: {", ".join(found_dangerous)}',
                        'evidence': f'Allow: {allow_header}',
                        'remediation': 'Restrict HTTP methods to only required ones',
                        'cve': None,
                        'cvss': 3.7
                    }
        except:
            pass

        return None

    def test_verbose_errors(self) -> Dict:
        """Test for verbose API error messages"""
        test_endpoints = [
            '/api/nonexistent',
            '/api/users/99999999',
            '/api/invalid'
        ]

        for endpoint in test_endpoints:
            try:
                url = f"{self.target}{endpoint}"
                response = self.session.get(url, timeout=5)

                indicators = [
                    'stack trace', 'exception', 'SQLException',
                    'at line', 'error in', '/var/www',
                    'traceback', 'debug'
                ]

                response_lower = response.text.lower()
                found = [i for i in indicators if i.lower() in response_lower]

                if found:
                    return {
                        'test': 'Verbose Error Messages',
                        'severity': 'LOW',
                        'description': 'API returns verbose error messages',
                        'evidence': f'Found: {", ".join(found)}',
                        'remediation': 'Use generic errors, log details server-side',
                        'cve': 'CWE-209',
                        'cvss': 3.7
                    }
            except:
                continue

        return None

    def test_api_documentation_exposure(self) -> Dict:
        """Test for exposed API documentation files"""
        doc_files = [
            '/api.yaml', '/openapi.yaml', '/swagger.yaml',
            '/api.json', '/openapi.json', '/postman.json'
        ]

        exposed_docs = []

        for doc in doc_files:
            try:
                url = f"{self.target}{doc}"
                response = self.session.get(url, timeout=5)

                if response.status_code == 200:
                    exposed_docs.append(doc)
            except:
                continue

        if exposed_docs:
            return {
                'test': 'API Documentation Files Exposed',
                'severity': 'INFO',
                'description': f'API documentation files accessible',
                'evidence': ', '.join(exposed_docs),
                'remediation': 'Remove docs from production or restrict access',
                'cve': None,
                'cvss': 0
            }

        return None
