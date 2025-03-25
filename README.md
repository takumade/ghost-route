# 👻 Ghost Route

A Python script to check Next.js sites for middleware vulnerabilities (CVE-2025-29927).

> [!WARNING]
> This tool is for educational purposes only. Do not use it on websites or systems you do not own or have explicit permission to test. Unauthorized testing may be illegal and unethical.

> [!DISCLAIMER]
> The author of this script is not responsible for any damage or legal issues that may arise from its use. Use at your own risk.

## Installation

Clone the repo

```bash
git clone https://github.com/takumade/ghost-route.git
cd ghost-route
```



## Usage

```bash
python ghost-route.py <url> <path>
```

## Example

```bash
python ghost-route.py https://example.com /admin
```

## License

MIT License

## Credits

- [CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927)
- [WriteUp](https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware)
- Rachid A.
- Yasser Allam
