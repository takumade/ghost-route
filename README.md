# 👻 Ghost Route

![Logo](https://raw.githubusercontent.com/takumade/ghost-route/main/ghost-route.png)

A Python script to check Next.js sites for corrupt middleware vulnerability (CVE-2025-29927).

The corrupt middleware vulnerability allows an attacker to bypass authentication and access protected routes by send a custom header `x-middleware-subrequest`. 

Next JS versions affected: 
- 11.1.4 and up

> [!WARNING]
> This tool is for educational purposes only. Do not use it on websites or systems you do not own or have explicit permission to test. Unauthorized testing may be illegal and unethical.

## Installation

Clone the repo

```bash
git clone https://github.com/takumade/ghost-route.git
cd ghost-route
```

Create and activate virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```


## Usage

```bash
python ghost-route.py <url> <path> <show_headers>
```

- `<url>`: Base URL of the Next.js site (e.g., https://example.com)
- `<path>`: Protected path to test (default: /admin)
- `<show_headers>`: Show response headers (default: False)
  

## Example

Basic Example
```bash
python ghost-route.py https://example.com /admin
```

Show Response Headers
```bash
python ghost-route.py https://example.com /admin True
```

## License

MIT License

## Credits

- [CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927)
- [Next.js and the corrupt middleware: the authorizing artifact](https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware)
- [Rachid A.](https://x.com/zhero___)
- [Yasser Allam](https://x.com/inzo____)
