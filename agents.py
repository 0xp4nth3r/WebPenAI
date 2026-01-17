import groq
import httpx
from config import Config


class AIAgents:
    def __init__(self):
        # Construct a plain httpx.Client and hand it to the groq client via
        # the `http_client` parameter. This avoids groq trying to construct
        # its own httpx client with a `proxies` kwarg that isn't supported by
        # the installed httpx version (which raises ``TypeError: __init__()
        # got an unexpected keyword argument 'proxies'``).
        http_client = httpx.Client(timeout=Config.TIMEOUT, follow_redirects=True)
        self.client = groq.Groq(api_key=Config.GROQ_API_KEY, http_client=http_client)
        
    def analyze_response(self, url, response_text, payload):
        prompt = f"""
        Analyze if this is SQL injection response:
        URL: {url}
        Payload used: {payload}
        Response: {response_text[:500]}
        
        Look for: SQL errors, different content, time delays, boolean differences.
        Return: VULNERABLE or SAFE
        """
        
        try:
            response = self.client.chat.completions.create(
                model=Config.GROQ_MODEL,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=50
            )
            return response.choices[0].message.content.strip()
        except:
            return "ERROR"
    
    def generate_payload(self, form_info):
        # Ask the AI to return a JSON object with the generated payload and
        # a hash (SHA256 hex). If the model doesn't follow the format, we
        # fall back to a simple payload and compute the hash locally.
        # Use doubled braces for the JSON example so the f-string does not
        # attempt to interpret them as format placeholders. Keep {form_info}
        # as a real placeholder to inject the form metadata.
        prompt = f"""
        You are an assistant that generates SQL injection payloads tailored to a
        target form. Return ONLY a JSON object with two keys:
        {{
          "payload": "the payload string",
          "hash": "sha256-hex-of-payload"
        }}

        Form fields: {form_info}
        Provide a payload optimized to reveal SQLi based on the form fields.
        Do not include any explanation or extra text.
        """

        try:
            response = self.client.chat.completions.create(
                model=Config.GROQ_MODEL,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=150
            )
            raw = response.choices[0].message.content.strip()
            # Try to parse JSON returned by the model
            import json, hashlib
            try:
                obj = json.loads(raw)
                payload = obj.get('payload') or obj.get('Payload')
                phash = obj.get('hash') or obj.get('hash_hex') or obj.get('digest')
                if payload and phash:
                    return {'payload': payload.strip(), 'hash': phash}
            except Exception:
                # model didn't return clean JSON; attempt to extract a payload
                pass

            # Fallback: treat entire model output as payload and compute hash locally
            payload = raw
            phash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
            return {'payload': payload, 'hash': phash}
        except Exception:
            # Final fallback: common tautology
            import hashlib
            payload = "' OR '1'='1"
            phash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
            return {'payload': payload, 'hash': phash}


class ClassifierAgent:
    """Simple rule-based classifier to pick 'risky' parameter names from forms or query links.

    This is intentionally lightweight: it uses common name tokens and input types
    to rank which parameters are more likely to be injectable.
    """
    def __init__(self):
        # tokens commonly associated with backend SQL inputs
        self.tokens = [
            'id', 'user', 'login', 'email', 'pass', 'name', 'search', 'q', 'query',
            'term', 'filter', 'sort', 'order', 'price', 'page', 'uid'
        ]

    def risky_params_from_form(self, form):
        names = [inp.get('name') for inp in form.get('inputs', []) if inp.get('name')]
        # prefer params that match tokens
        risky = [n for n in names if any(t in n.lower() for t in self.tokens)]
        if risky:
            return risky
        # fallback: return all textual inputs
        return [n for n in names if any(inp.get('type') in ('text', 'search', 'textarea') for inp in form.get('inputs', []) if inp.get('name')==n)]

    def risky_params_from_query(self, link):
        # link is {'url': full, 'params': [names]}
        params = link.get('params', [])
        risky = [p for p in params if any(t in p.lower() for t in self.tokens)]
        return risky if risky else params


class ReporterAgent:
    """Simple reporter which writes results to JSON and prints a compact summary."""
    def report(self, results, filename='results.json'):
        import json
        # Normalize results: if a finding was confirmed with a different payload,
        # prefer that payload in the saved result but keep the original in
        # `original_payload` for traceability.
        normalized = []
        for r in results:
            entry = dict(r)
            # Ensure URL-like objects are JSON serializable by converting to str
            if entry.get('url') is not None:
                entry['url'] = str(entry.get('url'))
            # If a form object contains an action that is a URL-like object,
            # stringify it as well.
            if entry.get('form') and isinstance(entry['form'], dict) and entry['form'].get('action') is not None:
                entry['form']['action'] = str(entry['form']['action'])
            confirmed = entry.get('confirmed')
            conf_payload = entry.get('confirmed_payload')
            if confirmed and conf_payload:
                # keep the original
                if 'original_payload' not in entry:
                    entry['original_payload'] = entry.get('payload')
                entry['payload'] = conf_payload
            normalized.append(entry)

        with open(filename, 'w') as f:
            json.dump(normalized, f, indent=2)

        # compact console summary
        vulns = [r for r in normalized if r.get('vulnerable')]
        print(f"\n[REPORT] {len(vulns)} vulnerable result(s) written to {filename}")
        for r in vulns:
            url = r.get('url')
            payload = r.get('payload')
            orig = r.get('original_payload')
            if orig and orig != payload:
                print(f" - {url}  payload={payload}  (original={orig})")
            else:
                print(f" - {url}  payload={payload}")

    def compute_severity(self, detected, confirmed=False):
        """Compute a human-friendly severity level for a finding.

        Inputs:
         - detected: dict as returned by `detect_vulnerabilities` (reason, score)
         - confirmed: bool whether the finding was confirmed with a reproducer payload

        Returns: dict {'level': 'LOW'|'MEDIUM'|'HIGH', 'score': float}
        """
        if not detected:
            return {'level': 'LOW', 'score': 0.0}

        base = float(detected.get('score', 0.0))
        reason = detected.get('reason', '')

        bonus = 0.0
        if reason == 'error':
            bonus += 0.3
        elif reason == 'time':
            bonus += 0.25
        elif reason == 'content_diff':
            bonus += 0.2
        elif reason == 'status_code_change':
            bonus += 0.2

        score = min(1.0, base + bonus)

        # confirmed findings are more severe
        if confirmed and score >= 0.5:
            level = 'HIGH'
        elif score >= 0.6:
            level = 'MEDIUM'
        elif score >= 0.3:
            level = 'LOW'
        else:
            level = 'INFO'

        return {'level': level, 'score': round(score, 3)}