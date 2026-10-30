import time
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup

from config import Config
from target_manager.scope_enforcer import is_path_in_scope, normalize_domain, resolve_and_check_ssrf

class Crawler:
    """
    Scope-enforced, rate-limited same-domain web crawler.
    Gathers URLs, HTML forms, and input parameters for analysis.
    """
    def __init__(self, target_url, in_scope="/*", out_of_scope="", max_pages=20, max_depth=2, 
                 max_req_per_sec=5, is_lab=False, stop_checker=None):
        self.start_url = target_url
        self.base_domain = normalize_domain(target_url)
        self.in_scope = in_scope
        self.out_of_scope = out_of_scope
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.min_delay = 1.0 / max(1, max_req_per_sec)
        self.is_lab = is_lab
        self.stop_checker = stop_checker

        self.visited_urls = set()
        self.discovered_forms = []
        self.discovered_endpoints = []
        self.last_req_time = 0.0

    def _rate_limit(self):
        """Enforce request delay according to authorized rate limits."""
        now = time.time()
        elapsed = now - self.last_req_time
        if elapsed < self.min_delay:
            time.sleep(self.min_delay - elapsed)
        self.last_req_time = time.time()

    def _is_url_crawlable(self, url):
        """Verify URL matches target domain, scheme, and authorized scope."""
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return False
            
            # Domain check (must be exact domain or subdomain of authorized target)
            host = parsed.netloc.split(":")[0].strip().lower()
            if host != self.base_domain and not host.endswith("." + self.base_domain):
                return False

            # In-scope / Out-of-scope path check
            in_scope, _ = is_path_in_scope(parsed.path or "/", self.in_scope, self.out_of_scope)
            if not in_scope:
                return False

            # SSRF check
            ssrf_ok, _ = resolve_and_check_ssrf(url, is_lab_target=self.is_lab)
            if not ssrf_ok:
                return False

            # Exclude media / binary files
            path_lower = parsed.path.lower()
            skip_exts = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.pdf', '.zip', '.tar', '.gz', '.mp4', '.mp3', '.css', '.woff', '.woff2')
            if any(path_lower.endswith(ext) for ext in skip_exts):
                return False

            return True
        except Exception:
            return False

    def crawl(self, log_callback=None):
        """
        Execute BFS crawling up to max_depth and max_pages.
        Returns dictionary of discovered URLs, forms, and pages.
        """
        queue = [(self.start_url, 0)]
        self.visited_urls.add(self.start_url)
        self.discovered_endpoints.append(self.start_url)

        headers = {"User-Agent": Config.USER_AGENT}

        while queue and len(self.visited_urls) <= self.max_pages:
            if self.stop_checker and self.stop_checker():
                if log_callback:
                    log_callback("Crawling halted by stop signal.")
                break

            current_url, depth = queue.pop(0)

            if log_callback:
                log_callback(f"Crawling [Depth {depth}]: {current_url}")

            self._rate_limit()

            try:
                resp = requests.get(
                    current_url,
                    headers=headers,
                    timeout=Config.DEFAULT_TIMEOUT,
                    verify=False,
                    allow_redirects=True
                )
                
                # Check final redirect destination for scope
                if not self._is_url_crawlable(resp.url):
                    continue

                if "text/html" not in resp.headers.get("Content-Type", ""):
                    continue

                soup = BeautifulSoup(resp.text, "html.parser")

                # Extract forms
                forms = soup.find_all("form")
                for form in forms:
                    action = form.get("action") or current_url
                    form_action_url = urljoin(current_url, action)
                    method = form.get("method", "GET").upper()
                    
                    inputs = []
                    for inp in form.find_all(["input", "textarea", "select"]):
                        name = inp.get("name")
                        if name:
                            inputs.append({
                                "name": name,
                                "type": inp.get("type", "text"),
                                "value": inp.get("value", "")
                            })
                    
                    self.discovered_forms.append({
                        "url": form_action_url,
                        "method": method,
                        "inputs": inputs,
                        "page_url": current_url
                    })

                # Queue next links if depth permits
                if depth < self.max_depth:
                    for a in soup.find_all("a", href=True):
                        link = urljoin(current_url, a['href'])
                        clean_link = link.split("#")[0] # Strip fragment
                        
                        if clean_link not in self.visited_urls and self._is_url_crawlable(clean_link):
                            self.visited_urls.add(clean_link)
                            self.discovered_endpoints.append(clean_link)
                            queue.append((clean_link, depth + 1))

            except Exception as e:
                if log_callback:
                    log_callback(f"Failed to crawl {current_url}: {str(e)}", level="WARN")

        return {
            "endpoints": list(self.discovered_endpoints),
            "forms": self.discovered_forms,
            "count": len(self.discovered_endpoints)
        }
