from flask import Flask, request, render_template_string, send_file
import socket, requests, csv, io

app = Flask(__name__)

common_ports = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 443: 'HTTPS', 3306: 'MySQL'
}

def banner_grab(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner
    except:
        return None

def geoip_lookup(ip):
    try:
        res = requests.get(f"https://ipapi.co/{ip}/json/")
        data = res.json()
        return f"{data.get('city', '')}, {data.get('region', '')}, {data.get('country_name', '')}"
    except:
        return "Unknown"

def cve_lookup(banner):
    try:
        res = requests.get(f"https://vulners.com/api/v3/search/lucene/?query={banner}")
        data = res.json()
        if data.get("data", {}).get("search"):
            return [item["title"] for item in data["data"]["search"][:3]]
        return []
    except:
        return []

def security_tip(port):
    tips = {
        23: "Telnet is insecure. Consider disabling it.",
        21: "FTP transmits data in plaintext. Use SFTP instead.",
        80: "Consider redirecting HTTP to HTTPS.",
        3306: "MySQL should not be exposed to the internet."
    }
    return tips.get(port, "")

def scan(ip):
    results = []
    for port in common_ports:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((ip, port))
            banner = banner_grab(ip, port)
            cves = cve_lookup(banner) if banner else []
            tip = security_tip(port)
            results.append({
                "port": port,
                "service": common_ports[port],
                "status": "OPEN",
                "banner": banner or "No banner",
                "cves": cves,
                "tip": tip
            })
            s.close()
        except:
            results.append({
                "port": port,
                "service": common_ports[port],
                "status": "CLOSED",
                "banner": "—",
                "cves": [],
                "tip": ""
            })
    return results

@app.route('/', methods=['GET', 'POST'])
def home():
    scan_results = []
    target_ip = ''
    location = ''
    if request.method == 'POST':
        target_ip = request.form['ip']
        location = geoip_lookup(target_ip)
        scan_results = scan(target_ip)

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cybersecurity Scanner</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-dark text-light">
        <div class="container mt-5">
            <h1 class="mb-4">🛡️ Cybersecurity Scanner Dashboard</h1>
            <form method="POST">
                <input type="text" name="ip" class="form-control mb-3" placeholder="Enter target IP" required value="{{ target_ip }}">
                <button type="submit" class="btn btn-primary">Scan</button>
            </form>
            {% if scan_results %}
                <h4 class="mt-4">Scan Results for {{ target_ip }} ({{ location }})</h4>
                <table class="table table-bordered table-striped mt-3">
                    <thead>
                        <tr><th>Port</th><th>Service</th><th>Status</th><th>Banner</th><th>CVE</th><th>Tip</th></tr>
                    </thead>
                    <tbody>
                        {% for r in scan_results %}
                        <tr>
                            <td>{{ r.port }}</td>
                            <td>{{ r.service }}</td>
                            <td>{{ r.status }}</td>
                            <td>{{ r.banner }}</td>
                            <td>
                                {% for cve in r.cves %}
                                    <div>{{ cve }}</div>
                                {% endfor %}
                            </td>
                            <td>{{ r.tip }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                <form action="/export" method="POST">
                    <input type="hidden" name="ip" value="{{ target_ip }}">
                    <button type="submit" class="btn btn-success">Export CSV</button>
                </form>
            {% endif %}
        </div>
    </body>
    </html>
    """, scan_results=scan_results, target_ip=target_ip, location=location)

@app.route('/export', methods=['POST'])
def export():
    ip = request.form['ip']
    results = scan(ip)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Port', 'Service', 'Status', 'Banner', 'CVE', 'Tip'])
    for r in results:
        writer.writerow([
            r['port'], r['service'], r['status'], r['banner'],
            '; '.join(r['cves']), r['tip']
        ])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv',
                     download_name=f'scan_{ip}.csv', as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)