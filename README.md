# Cybersecurity-Scanner-Dashboard
A lightweight Flask-based cybersecurity scanner that checks common ports on a target IP, grabs service banners, looks up known vulnerabilities (CVEs), traces GeoIP location, and provides security tips. Results are displayed in a dashboard and can be exported as a CSV for reporting or analysis.
# 🛡️ Cybersecurity Scanner Dashboard
A lightweight Flask-based web application that scans a target IP address for open ports, grabs service banners, checks for known vulnerabilities (CVEs), traces GeoIP location, and provides security tips. Results are displayed in a dashboard and can be exported as a CSV file.
## 🚀 Features
- 🔍 **Port Scanning** — Checks common ports (FTP, SSH, HTTP, etc.) for open status
- 🧾 **Banner Grabbing** — Retrieves service banners to identify running software
- 🧨 **CVE Lookup** — Queries Vulners API to find known vulnerabilities
- 🌍 **GeoIP Location** — Displays the geographical location of the target IP
- 🛡️ **Security Tips** — Offers recommendations for insecure or exposed services
- 📁 **CSV Export** — Allows users to download scan results for reporting
## 🧰 Technologies Used
- **Python 3.x**
- **Flask** — Web framework
- **Requests** — For API calls
- **Bootstrap 5** — For responsive UI
- **ipapi.co API** — For GeoIP location lookup
- **vulners.com API** — For CVE search
