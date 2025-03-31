# tcpscan

## Description
tcpscan is a TCP port scanner and lightweight service fingerprinting tool. It performs a TCP SYN scan to identify open ports on a target host and attempts to classify the service running on each open port by performing active probing—without relying on default port numbers.

The scanner distinguishes between different server behaviors (e.g., immediate server banners, HTTP/TLS handshakes, and generic data exchanges) and works over both plain TCP and TLS. The tool is designed to mimic the functionality of tools like nmap -sS and nmap -sV, but with a minimal and focused implementation.

## Usage

```sh
tcpscan.py -p [port_range] target
```

-p `port_range`
    Optional. A single port (e.g., 443) or a range (20-100).
    If omitted, tcpscan scans the following common ports: 21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080

`target`
    Required. IP address of the target host (e.g., 192.168.0.5). The domain name can also be used.

## Installation

### Prerequistes
- **Python 3.x**
- **pip** (Python package manager)

### **Required Dependencies**
The tool relies on **socket** for packet capture and analysis.

#### **Installation Steps**
1. **Clone the Repository**
  ```sh
  git clone https://github.com/kailash-anand/tcpscan.git
  cd tcpscan
  ```

2. **Create a Virtual Environment**
  ```sh
  python3 -m venv venv
  source venv/bin/activate
  ```

3. **Install it as a tool**
  ```sh
  pip install -e .
  ```

## Test Runs
```sh
tcpscan -p 80 www.google.com
```
Scanning for open ports...
Open ports identified: [80]
Connecting to open ports...
------------------------------------
Host: www.google.com:80
Type: ( 3 ) HTTP server
Response: HTTP/1.0 200 OK..Date: Mon, 31 Mar 2025 18:41:33 GMT..Expires: -1..Cache-Control: private, max-age=0..Content-Type: text/html; charset=ISO-8859-1..Content-Security-Policy-Report-Only: object-src 'none';base-uri 'self';script-src 'nonce-AvtUhjzdJXIiFuODQmIZEA' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp..P3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."..Server: gws..X-XSS-Protection: 0..X-Frame-Options: SAMEORIGIN..Set-Cookie: AEC=AVcja2dV2qVKqI15rGykPQ8Z0kBMCGh_mednmOHaHmBGABq969aEeCUviA; expires=Sat, 27-Sep-2025 18:41:33 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax..Set-Cookie: NID=522=nVV7LplddeqOEmJtuF3ZjRtScxyikS3O6Z4ibt_Yu8fZm4gs1k4X44syWBNkEySwvg2gVn0Il0PXP90veN-T-Uqkiffi8l58LXOrof21OJox-7fvOJ2s51IQdsZS4G7xoI9Q2qemrLRDXa1rsff1kpSDEXQaFdGex_N-oiUwKNl7m04DljLtCEFX3fyB8IT32rLhAOvTNxiKQ-ZCtaHJ7zo; expires=Tue, 30-Sep-2025 18:41:33 GMT; path=/; domain=.google.com; HttpOnly..Accept-Rang

```sh
tcpscan imap.gmail.com
``` 
Scanning for open ports...
Open ports identified: [587, 993]
Connecting to open ports...
------------------------------------
Host: imap.gmail.com:587
Type: ( 1 ) TCP server-initiated
Response: 220 smtp.gmail.com ESMTP 6a1803df08f44-6eec9797b3asm49500706d6.100 - gsmtp..
------------------------------------
Host: imap.gmail.com:993
Type: ( 2 ) TLS server-initiated
Response: * OK Gimap ready for requests from 129.49.100.67 lg17mb108135982qvb.. 

## Notes
- The scanner uses a 3-second timeout when waiting for service responses.
- It prints printable ASCII characters and replaces non-printable bytes with dots (.).
- TLS support uses Python's built-in ssl module to wrap TCP sockets.
- The scanner is single-host only (no subnet scanning).
