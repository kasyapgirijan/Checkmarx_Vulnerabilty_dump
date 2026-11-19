"""Readable finding categories from CWE IDs, shared by the exporter and the PostgreSQL loader."""
import re

# CWE -> readable category. Covers the CWEs behind most SCA, container and SAST findings;
# anything else falls back to keywords in the finding name, then to "Other".
CWE_CATEGORIES = {
    'Code/Command Injection (RCE)': (77, 78, 88, 94, 95, 96, 97, 1336, 917),
    'SQL/NoSQL Injection': (89, 564, 943),
    'Other Injection': (74, 75, 90, 91, 93, 113, 117, 134, 643, 652, 1236),
    'Cross-Site Scripting (XSS)': (79, 80, 83, 87),
    'Deserialization': (502,),
    'Path Traversal / File Access': (22, 23, 35, 36, 59, 73, 434),
    'Server-Side Request Forgery (SSRF)': (918,),
    'XML External Entity (XXE)': (611, 776, 827),
    'Open Redirect': (601,),
    'Cross-Site Request Forgery (CSRF)': (352,),
    'Prototype Pollution': (1321,),
    'Hardcoded Credentials / Secrets': (798, 259, 321, 256, 522),
    'Authentication': (287, 288, 290, 294, 306, 307, 521, 620, 640),
    'Authorization / Access Control': (250, 266, 269, 276, 284, 285, 639, 732, 862, 863, 1220),
    'Session Management': (384, 613, 614, 1004),
    'Cryptography / TLS': (295, 297, 310, 311, 319, 326, 327, 328, 329, 330, 338, 757, 759, 760, 780, 916),
    'Information Disclosure': (200, 201, 209, 215, 359, 497, 532, 538),
    'Denial of Service': (400, 405, 407, 674, 770, 834, 835, 1333),
    'Memory Corruption': (119, 120, 121, 122, 125, 131, 190, 191, 415, 416, 476, 680, 787, 822, 824),
    'Race Condition': (362, 367),
    'Input Validation': (20, 129, 1284, 1287),
}
CWE_TO_CATEGORY = {cwe: name for name, cwes in CWE_CATEGORIES.items() for cwe in cwes}
# Checked in order against the finding/query name when no CWE maps (SAST query names, KICS titles).
KEYWORD_CATEGORIES = [
    (('deserializ',), 'Deserialization'),
    (('sql_injection', 'sql injection', 'sqli', 'nosql'), 'SQL/NoSQL Injection'),
    (('command_injection', 'command injection', 'code_injection', 'code injection', 'remote code',
      'rce', 'os_command', 'expression_language'), 'Code/Command Injection (RCE)'),
    (('xss', 'cross site scripting', 'cross-site scripting'), 'Cross-Site Scripting (XSS)'),
    (('ssrf', 'server side request', 'server-side request'), 'Server-Side Request Forgery (SSRF)'),
    (('xxe', 'xml external', 'xml_external'), 'XML External Entity (XXE)'),
    (('path_traversal', 'path traversal', 'directory traversal'), 'Path Traversal / File Access'),
    (('open_redirect', 'open redirect'), 'Open Redirect'),
    (('csrf', 'cross site request', 'cross-site request'), 'Cross-Site Request Forgery (CSRF)'),
    (('prototype pollution', 'prototype_pollution'), 'Prototype Pollution'),
    (('hardcoded', 'hard_coded', 'hard-coded', 'secret', 'password', 'api key', 'token'),
     'Hardcoded Credentials / Secrets'),
    (('injection',), 'Other Injection'),
    (('denial of service', 'redos', 'resource exhaustion'), 'Denial of Service'),
    (('crypto', 'cipher', 'tls', 'ssl', 'weak_hash', 'weak hash', 'encryption'), 'Cryptography / TLS'),
    (('privacy', 'information exposure', 'information_exposure', 'leak', 'disclosure'), 'Information Disclosure'),
]


def cwe_numbers(value):
    """'CWE-79', 79, ['CWE-79', 502], '79; 502' -> [79, 502]."""
    items = value if isinstance(value, (list, tuple)) else [value]
    found = []
    for item in items:
        found += [int(n) for n in re.findall(r'\d+', str(item if item is not None else ''))]
    return list(dict.fromkeys(found))


def cwe_text(value):
    return '; '.join(f'CWE-{n}' for n in cwe_numbers(value))


def categorize(cwes, *texts, engine=''):
    """Readable category from CWEs, else from keywords in the finding's name or title."""
    for number in cwe_numbers(cwes):
        if number in CWE_TO_CATEGORY:
            return CWE_TO_CATEGORY[number]
    if engine == 'secrets':
        return 'Hardcoded Credentials / Secrets'
    text = ' '.join(str(t or '') for t in texts).lower()
    for words, name in KEYWORD_CATEGORIES:
        if any(w in text for w in words):
            return name
    if engine == 'kics':
        return 'IaC Misconfiguration'
    return 'Other'
