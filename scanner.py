from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import time
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service
from config import Config
import os
import subprocess
from pathlib import Path

class SQLScanner:
    def __init__(self):
        options = webdriver.ChromeOptions()
        if Config.HEADLESS:
            options.add_argument('--headless')
        options.add_argument(f'user-agent={Config.USER_AGENT}')
        options.add_argument('--no-sandbox')
        project_root = Path(__file__).resolve().parent
        bundled_chrome = project_root / 'chrome-linux64' / 'chrome'

        chrome_version = None
        if bundled_chrome.exists() and os.access(bundled_chrome, os.X_OK):
            options.binary_location = str(bundled_chrome)
            try:
                out = subprocess.check_output([str(bundled_chrome), '--version'], stderr=subprocess.STDOUT)
                out = out.decode(errors='ignore')
                # Typical output: 'Google Chrome 100.0.4896.127'
                parts = [p for p in out.strip().split() if any(c.isdigit() for c in p)]
                if parts:
                    # take the first numeric token and normalize to major.minor.patch
                    numeric = parts[0].strip()
                    chrome_version = '.'.join(numeric.split('.')[:3])
            except Exception:
                chrome_version = None

        # If a CHROME_DRIVER_PATH is provided in config and points at an
        # existing file, use it directly instead of auto-downloading.
        driver_path = Config.CHROME_DRIVER_PATH
        service_path = None
        if driver_path and Path(driver_path).exists():
            # Heuristic: ensure the provided path is actually a chromedriver
            # binary (it should return a 'ChromeDriver' string from `--version`).
            try:
                out = subprocess.check_output([str(driver_path), '--version'], stderr=subprocess.STDOUT)
                if b"ChromeDriver" in out:
                    service_path = driver_path
                else:
                    # Not a chromedriver binary; ignore and fall back to manager.
                    service_path = None
            except Exception:
                service_path = None

        try:
            if service_path:
                service = Service(service_path)
            else:
                # If we were able to determine a chrome version, pass it to
                # the ChromeDriverManager to avoid it probing the system.
                try:
                        if chrome_version:
                            driver_bin = ChromeDriverManager(driver_version=chrome_version).install()
                        else:
                            driver_bin = ChromeDriverManager().install()
                except AttributeError as err:
                    # webdriver_manager may attempt to parse a system browser
                    # version and return None which leads to an AttributeError
                    # (the original error you saw). Give a clear actionable
                    # message instead of letting a low-level exception bubble up.
                    raise RuntimeError(
                        "Could not determine a Chrome browser on the system. "
                        "Please either install Google Chrome on your machine, "
                        "provide a path to an existing chromedriver binary via "
                        "the CHROME_DRIVER_PATH config, or put a Chromium binary "
                        "at chrome-linux64/chrome in the project root."
                    ) from err
                # webdriver_manager returned a path. Validate it's an executable
                # chromedriver binary. Sometimes archives contain additional
                # files (LICENSE, THIRD_PARTY_NOTICES) and the automatic
                # selection may pick the wrong file.
                def _is_likely_driver(p: str) -> bool:
                    """Return True if path looks like a chromedriver executable.

                    Checks:
                    - is a file
                    - readable
                    - size > 1KB
                    - content starts with ELF magic (\x7fELF) or a shebang (#!)
                    - executable bit set
                    """
                    try:
                        if not (os.path.isfile(p) and os.path.getsize(p) > 1024 and os.access(p, os.R_OK)):
                            return False
                        # quick content-based check
                        with open(p, 'rb') as fh:
                            header = fh.read(4)
                        if header.startswith(b'\x7fELF') or header.startswith(b"#!"):
                            # also prefer executable bit
                            return os.access(p, os.X_OK)
                        return False
                    except Exception:
                        return False

                if not _is_likely_driver(driver_bin):
                    # Search the driver directory for a better candidate.
                    driver_dir = os.path.dirname(driver_bin)
                    candidates = []
                    try:
                        for name in os.listdir(driver_dir):
                            lower = name.lower()
                            if 'chromedriver' in lower and 'third_party' not in lower and 'license' not in lower:
                                full = os.path.join(driver_dir, name)
                                if _is_likely_driver(full):
                                    candidates.append(full)
                    except Exception:
                        candidates = []

                    if candidates:
                        # pick the first executable candidate
                        driver_bin = candidates[0]
                    else:
                        # If there is a non-executable file named exactly
                        # 'chromedriver' in the directory, try to make it
                        # executable and use it. This handles cases where
                        # webdriver-manager unpacks the binary without the
                        # executable bit set.
                        fallback = os.path.join(driver_dir, 'chromedriver')
                        if os.path.exists(fallback):
                            try:
                                os.chmod(fallback, 0o755)
                                if _is_likely_driver(fallback):
                                    driver_bin = fallback
                                else:
                                    raise RuntimeError(
                                        f"Found '{fallback}' but it does not appear to be a valid executable chromedriver."
                                    )
                            except Exception as e:
                                raise RuntimeError(
                                    f"Could not make '{fallback}' executable or validate it: {e}"
                                ) from e
                    # If after looking for candidates and attempting a chmod
                    # the returned driver_bin still doesn't look valid, fail
                    # with a clear error message.
                    if not _is_likely_driver(driver_bin):
                        raise RuntimeError(
                            f"Downloaded chromedriver at '{driver_bin}' does not appear to be an executable driver. "
                            f"Please provide a valid chromedriver binary via CHROME_DRIVER_PATH or place a compatible "
                            f"chromedriver in the project cache. Driver directory contents: {os.listdir(os.path.dirname(driver_bin)) if os.path.isdir(os.path.dirname(driver_bin)) else 'N/A'}"
                        )

                service = Service(driver_bin)

            self.driver = webdriver.Chrome(service=service, options=options)
        except Exception:
            # As a last resort, raise the exception so the caller can see
            # what went wrong (e.g., missing chrome/chromedriver). This keeps
            # behavior explicit instead of silently swallowing errors.
            raise
        self.wait = WebDriverWait(self.driver, Config.TIMEOUT)
        
    def find_forms(self, url):
        self.driver.get(url)

        # Wait for the page to finish loading (up to Config.TIMEOUT seconds).
        try:
            WebDriverWait(self.driver, Config.TIMEOUT).until(
                lambda d: d.execute_script('return document.readyState') == 'complete'
            )
        except Exception:
            # if waiting fails, continue — we will still try to read the DOM
            pass

        # Save page snapshot for debugging when no forms are found
        try:
            safe_name = url.replace('://', '_').replace('/', '_')
            html_path = f"page_snapshot_{safe_name}.html"
            png_path = f"page_snapshot_{safe_name}.png"
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(self.driver.page_source)
            try:
                self.driver.save_screenshot(png_path)
            except Exception:
                pass
        except Exception:
            html_path = None
            png_path = None

        forms = []
        page_forms = self.driver.find_elements(By.TAG_NAME, 'form')

        for i, form in enumerate(page_forms):
            inputs = form.find_elements(By.TAG_NAME, 'input')
            textareas = form.find_elements(By.TAG_NAME, 'textarea')
            selects = form.find_elements(By.TAG_NAME, 'select')

            form_data = {
                'index': i,
                'action': form.get_attribute('action') or url,
                'method': form.get_attribute('method') or 'get',
                'inputs': []
            }

            for inp in inputs:
                inp_type = inp.get_attribute('type') or 'text'
                # include several common input types; treat unknown types as text
                if inp_type in ['text', 'search', 'email', 'password', 'number', 'tel', 'url', 'textarea']:
                    name = inp.get_attribute('name') or inp.get_attribute('id')
                    form_data['inputs'].append({
                        'name': name,
                        'type': inp_type
                    })

            for textarea in textareas:
                name = textarea.get_attribute('name') or textarea.get_attribute('id')
                form_data['inputs'].append({
                    'name': name,
                    'type': 'textarea'
                })

            for sel in selects:
                name = sel.get_attribute('name') or sel.get_attribute('id')
                form_data['inputs'].append({
                    'name': name,
                    'type': 'select'
                })

            # filter out inputs with no name/id (we can't submit them)
            valid_inputs = [i for i in form_data['inputs'] if i.get('name')]
            if valid_inputs:
                form_data['inputs'] = valid_inputs
                forms.append(form_data)

        # If no forms found via Selenium, try a requests-based fallback
        if not forms:
            try:
                r = self._requests_get(url)
                html = r['source']
                parsed_forms = self._parse_html_forms(html, url)
                if parsed_forms:
                    return parsed_forms
            except Exception:
                pass

        return forms
    
    def test_form(self, form_data, payload):
        url = form_data['action']
        method = form_data['method'].lower()

        if method == 'get':
            params = {}
            for inp in form_data['inputs']:
                # keep existing param names, use payload for all
                params[inp['name']] = payload

            param_str = '&'.join([f"{k}={v}" for k, v in params.items()])
            test_url = f"{url}?{param_str}" if '?' not in url else f"{url}&{param_str}"

            start_time = time.time()
            self.driver.get(test_url)
            load_time = time.time() - start_time

            page_source = self.driver.page_source
            current_url = self.driver.current_url

            # fallback: if page is empty, try requests
            if not page_source.strip():
                try:
                    r = self._requests_get(test_url)
                    return r
                except Exception:
                    pass

            return {
                'url': current_url,
                'source': page_source,
                'time': load_time
            }

        if method == 'post':
            # find the form element by index (collected in find_forms)
            try:
                forms = self.driver.find_elements(By.TAG_NAME, 'form')
                form_elem = forms[form_data.get('index', 0)]
            except Exception:
                # fallback: try to navigate to the action URL and use requests
                try:
                    r = self._requests_post(url, {inp['name']: payload for inp in form_data['inputs']})
                    return r
                except Exception:
                    return None

            # fill inputs
            for inp in form_data['inputs']:
                name = inp.get('name')
                if not name:
                    continue
                try:
                    try:
                        field = form_elem.find_element(By.NAME, name)
                    except Exception:
                        field = form_elem.find_element(By.ID, name)
                    # clear and send payload
                    field.clear()
                    field.send_keys(payload)
                except Exception:
                    # if we can't find the field, set via JS
                    try:
                        self.driver.execute_script(
                            "var f=document.getElementsByName(arguments[0]); if(f && f[0]) f[0].value=arguments[1];",
                            name,
                            payload,
                        )
                    except Exception:
                        pass

            # submit the form
            start_time = time.time()
            try:
                # try native submit
                form_elem.submit()
            except Exception:
                try:
                    submit_btn = form_elem.find_element(By.XPATH, ".//input[@type='submit']|.//button[@type='submit']")
                    submit_btn.click()
                except Exception:
                    # as a last resort, navigate to action with requests
                    try:
                        r = self._requests_post(url, {inp['name']: payload for inp in form_data['inputs']})
                        return r
                    except Exception:
                        return None

            load_time = time.time() - start_time
            page_source = self.driver.page_source
            current_url = self.driver.current_url
            return {
                'url': current_url,
                'source': page_source,
                'time': load_time,
            }

        return None

    def test_url(self, url):
        """Load a full URL and return the same response dict used by test_form."""
        start_time = time.time()
        self.driver.get(url)
        load_time = time.time() - start_time

        page_source = self.driver.page_source
        current_url = self.driver.current_url

        return {
            'url': current_url,
            'source': page_source,
            'time': load_time
        }

    def find_query_params(self, base_url):
        """Return a list of dicts {'url': full_href, 'params': [param names]} for links on the page that contain query strings.

        The caller can then substitute payloads into those params to test for injection.
        """
        # Ensure page is loaded
        try:
            WebDriverWait(self.driver, 5).until(
                lambda d: d.execute_script('return document.readyState') == 'complete'
            )
        except Exception:
            pass

        anchors = self.driver.find_elements(By.TAG_NAME, 'a')
        results = []
        from urllib.parse import urljoin, urlparse, parse_qs

        for a in anchors:
            href = a.get_attribute('href')
            if not href:
                continue
            # normalize relative URLs
            full = urljoin(base_url, href)
            parsed = urlparse(full)
            if parsed.query:
                qs = parse_qs(parsed.query)
                params = list(qs.keys())
                results.append({'url': full, 'params': params})

        # fallback: if no anchors found, try requests-based parsing
        if not results:
            try:
                r = self._requests_get(base_url)
                parsed_links = self._parse_html_links(r['source'], base_url)
                if parsed_links:
                    return parsed_links
            except Exception:
                pass

        return results

    def _parse_html_forms(self, html, base_url):
        # Lightweight HTML parser to extract form actions, methods and input names
        from html.parser import HTMLParser
        from urllib.parse import urljoin

        class FormParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.forms = []
                self._current = None

            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == 'form':
                    self._current = {'action': attrs.get('action', base_url), 'method': attrs.get('method', 'get').lower(), 'inputs': []}
                elif tag == 'input' and self._current is not None:
                    name = attrs.get('name') or attrs.get('id')
                    itype = attrs.get('type', 'text')
                    self._current['inputs'].append({'name': name, 'type': itype})
                elif tag == 'textarea' and self._current is not None:
                    name = attrs.get('name') or attrs.get('id')
                    self._current['inputs'].append({'name': name, 'type': 'textarea'})
                elif tag == 'select' and self._current is not None:
                    name = attrs.get('name') or attrs.get('id')
                    self._current['inputs'].append({'name': name, 'type': 'select'})

            def handle_endtag(self, tag):
                if tag == 'form' and self._current is not None:
                    # filter empty names
                    self._current['inputs'] = [i for i in self._current['inputs'] if i.get('name')]
                    self.forms.append(self._current)
                    self._current = None

        p = FormParser()
        p.feed(html)
        # normalize actions
        for f in p.forms:
            f['action'] = urljoin(base_url, f['action'])
        return p.forms

    def _parse_html_links(self, html, base_url):
        from html.parser import HTMLParser
        from urllib.parse import urljoin, urlparse, parse_qs

        class LinkParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.links = []

            def handle_starttag(self, tag, attrs):
                if tag == 'a':
                    attrs = dict(attrs)
                    href = attrs.get('href')
                    if href:
                        self.links.append(href)

        p = LinkParser()
        p.feed(html)
        results = []
        for href in p.links:
            full = urljoin(base_url, href)
            parsed = urlparse(full)
            if parsed.query:
                qs = parse_qs(parsed.query)
                params = list(qs.keys())
                results.append({'url': full, 'params': params})
        return results

    # --- HTTP fallbacks using requests ---
    def _requests_get(self, url):
        import requests
        headers = {"User-Agent": Config.USER_AGENT}
        r = requests.get(url, headers=headers, timeout=Config.TIMEOUT)
        return {'url': r.url, 'source': r.text, 'time': r.elapsed.total_seconds()}

    def _requests_post(self, url, data):
        import requests
        headers = {"User-Agent": Config.USER_AGENT}
        r = requests.post(url, data=data, headers=headers, timeout=Config.TIMEOUT)
        return {'url': r.url, 'source': r.text, 'time': r.elapsed.total_seconds()}
    
    def detect_vulnerabilities(self, response, payload, baseline_source=None, baseline_time=None):
        """Return a dict with detection result and reason to reduce false positives.

        Returns: {'vulnerable': bool, 'reason': str or None, 'score': float}
        reason can be: 'time', 'error', 'content_diff', 'status_code_change'
        """
        import re
        from difflib import SequenceMatcher

        src = (response.get('source') or '')
        source_lower = src.lower()

        # Time-based detection (use baseline if available)
        resp_time = float(response.get('time') or 0)
        if baseline_time:
            # consider significant delay if > baseline + 3 seconds
            if resp_time > float(baseline_time) + 3:
                return {'vulnerable': True, 'reason': 'time', 'score': min(1.0, (resp_time - float(baseline_time)) / 5.0)}
        else:
            # fallback: absolute threshold
            if resp_time > 5:
                return {'vulnerable': True, 'reason': 'time', 'score': 0.6}

        # More conservative error-based detection: use regexes for known DB error messages
        db_error_patterns = [
            r"you have an error in your sql syntax",
            r"warning: mysql",
            r"mysql_fetch|mysql_num_rows|mysql_query",
            r"pg::syntaxerror|pg_error|pgsql",
            r"syntax error at or near",
            r"unclosed quotation mark after the character string",
            r"oledb|odbc|sqlstate",
            r"sqlsyntaxerror",
            r"data error|database error",
        ]

        for pat in db_error_patterns:
            try:
                if re.search(pat, source_lower):
                    return {'vulnerable': True, 'reason': 'error', 'score': 0.95}
            except re.error:
                continue

        # status code change detection
        if 'status' in response and baseline_source is not None and isinstance(baseline_source, dict):
            base_status = baseline_source.get('status')
            if base_status and response.get('status') and response.get('status') != base_status:
                return {'vulnerable': True, 'reason': 'status_code_change', 'score': 0.7}

        # content-diff detection (compare to baseline_source text if available)
        if baseline_source and isinstance(baseline_source, str) and baseline_source.strip():
            base = baseline_source
            try:
                ratio = SequenceMatcher(None, base, src).ratio()
            except Exception:
                ratio = 1.0

            # require more significant divergence and non-trivial page size
            if ratio < 0.90 and max(len(base), len(src)) > 400:
                score = 1.0 - ratio
                return {'vulnerable': True, 'reason': 'content_diff', 'score': score}

        return {'vulnerable': False, 'reason': None, 'score': 0.0}
    
    def close(self):
        self.driver.quit()