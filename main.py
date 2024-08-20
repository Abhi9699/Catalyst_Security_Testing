import json
from fastapi import APIRouter, FastAPI, HTTPException, Response
from fastapi.responses import JSONResponse
from datetime import datetime
import urllib.parse
import os
import time
import subprocess
import requests
from zapv2 import ZAPv2

app = FastAPI()
router = APIRouter()

def start_docker():
    docker_command = (
        'docker run --name testphp -d -u zap -p 8080:8080 '
        'zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 '
        '-config api.disablekey=true -config api.addrs.addr.name=.* '
        '-config api.addrs.addr.regex=true'
    )
    subprocess.run(docker_command, shell=True, check=True)
    return 'Security test is in progress...'

@router.post('/SecurityTest/')
def application_scan(targetUrl: str, userId: str, scanningType: str):
    start_docker()
    time.sleep(50)
    
    domain_name = urllib.parse.urlparse(targetUrl).netloc
    target = targetUrl
    apiKey = 'changeMe'
    
    zap = ZAPv2(apikey=apiKey)

    print(f'Spidering target {target}')
    scanID = zap.spider.scan(target)
    while int(zap.spider.status(scanID)) < 100:
        print(f'Spider progress %: {zap.spider.status(scanID)}')
        time.sleep(1)
    print('Security scan completed!')

    st = 0
    pg = 5000
    alert_dict = {}
    alert_count = 0
    alerts = zap.alert.alerts(baseurl=target, start=st, count=pg)
    blacklist = [1, 2]
    while len(alerts) > 0:
        print(f'Reading {pg} alerts from {st}')
        alert_count += len(alerts)
        for alert in alerts:
            plugin_id = alert.get('pluginId')
            if plugin_id in blacklist:
                continue
            if alert.get('risk') == 'High':
                continue
            if alert.get('risk') == 'Informational':
                continue
        st += pg
        alerts = zap.alert.alerts(start=st, count=pg)
    print(f'Total number of alerts: {alert_count}')

    headers = {
        'Accept': 'application/json'
    }
    
    report_types = [
        {"format": "pdf", "path": "/home/zap/ScannedReport.pdf"},
        {"format": "html", "path": "/home/zap/ScannedReport.html"},
        {"format": "json", "path": "/home/zap/ScannedReport.json"},
    ]
    
    container_name = "testphp"
    
    for report in report_types:
        report_format = report["format"]
        remote_filepath = report["path"]
        local_filename = f"ScannedReport.{report_format}"

        # Generate the report
        r = requests.get(f'http://localhost:8080/HTML/reports/action/generate/', params={
            'title': 'TestRig Scan Report', 'template': f'traditional-{report_format}', 'reportFileName': 'ScannedReport'
        }, headers=headers)

        if r.status_code == 200:
            print(f"{report_format.upper()} report generated successfully.")
        else:
            print(f"Failed to generate {report_format.upper()} report: {r.text}")

        time.sleep(5)  # Ensure the report is generated

        try:
            # Copy the report from the container
            subprocess.run(["docker", "cp", f"{container_name}:{remote_filepath}", local_filename], check=True)
            print(f"Report '{local_filename}' copied successfully.")
            # Uncomment the following lines to upload the report to S3
            # s3 = boto3.client('s3')
            # timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            # s3.upload_file(local_filename, 'catalystsecuritytesting', f"{domain_name}/{timestamp}/{local_filename}")
            # print("File Uploaded Successfully")
        except subprocess.CalledProcessError as e:
            print(f"Error copying {report_format.upper()} report: {e}")

    subprocess.run(f'docker container stop {container_name}', shell=True, check=True)
    time.sleep(5)
    subprocess.run(f'docker container rm {container_name}', shell=True, check=True)

    return "Security Scan Completed"

@router.post("/log_defects/")
async def log_defects(report_name: str):
    api_endpoint = 'https://walrus-app-aidtw.ondigitalocean.app/api/defect/new'

    headers = {
        'Content-Type': 'application/json',
    }

    cookies = {
    'access_token': 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImQ5OmU1OjM3OjFmOjU5OmIyOmI3OjE4OjEyOjcwOmYzOmI4OjM4OjFlOmZjOjkxIiwidHlwIjoiSldUIn0.eyJhdWQiOltdLCJhenAiOiIzOTA0NjgzNzM1MDU0NjRkYWMzMjJmYmEyZTRkMjQ1MiIsImV4cCI6MTcyNDEzNzExOCwiaWF0IjoxNzI0MDUwNzE4LCJpc3MiOiJodHRwczovL3Rlc3RyaWctZGV2ZWxvcG1lbnQudWsua2luZGUuY29tIiwianRpIjoiMWU2ZjY3ODktZjk4YS00Yzg2LWI2ODAtY2JjNGZjMTcyZmE4Iiwib3JnX2NvZGUiOiJvcmdfNTg0ZTM4NGNjZTYiLCJwZXJtaXNzaW9ucyI6W10sInNjcCI6WyJvcGVuaWQiLCJwcm9maWxlIiwiZW1haWwiLCJvZmZsaW5lIl0sInN1YiI6ImtwX2ZiMTkxOGJmNzVjNDRmN2JiYzU4ZmZmYjBmOTczYzRkIn0.sJmUNKO1TSHFhikDvMXPxMY7PCrggx_0o8G4_tnuigSCbxpUsABFSIH4AlW6vZoDma6y4wytrUKJni5ASQLfhTlg38zeYWTM-6wKvSa1-J_gdHA_URJdf4O5Bg5mnSb-tNMtY6Je48ymQcBJUnn50SfWkOrd2bGg5e0FzR7KrX-8NBDqTfnDg7TCxkSU5fo_mzpNQbPt59s3pgBlgWXuvqsDUFAahyRUuLAXojAHa-xtsSbUj9zMfepjbKcrTw9vN2PUstz14b3X3sxuqog7ITSPmlYD2JeMD8qhoR3qP78kzYcvQstEtDRVM0zwNZAYCI_vtDjQnt1Z9vF54vbtQA',
    'id_token': 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImQ5OmU1OjM3OjFmOjU5OmIyOmI3OjE4OjEyOjcwOmYzOmI4OjM4OjFlOmZjOjkxIiwidHlwIjoiSldUIn0.eyJhdF9oYXNoIjoiUlN3RFEycG85TjRSTFZlQmNFWHFpZyIsImF1ZCI6WyIzOTA0NjgzNzM1MDU0NjRkYWMzMjJmYmEyZTRkMjQ1MiJdLCJhdXRoX3RpbWUiOjE3MjQwNTA3MTcsImF6cCI6IjM5MDQ2ODM3MzUwNTQ2NGRhYzMyMmZiYTJlNGQyNDUyIiwiZW1haWwiOiJhYmhpc2hla2pAdGVzdHJpZy5jby5pbiIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJleHAiOjE3MjQwNTQzMTgsImZhbWlseV9uYW1lIjoiamFkYXYiLCJnaXZlbl9uYW1lIjoiYWJoaXNoZWsiLCJpYXQiOjE3MjQwNTA3MTgsImlzcyI6Imh0dHBzOi8vdGVzdHJpZy1kZXZlbG9wbWVudC51ay5raW5kZS5jb20iLCJqdGkiOiIzOGFlYTdmMi0wMmQ3LTQ0ZGUtODE2Zi1mZDU4NGRlNWMxNzIiLCJuYW1lIjoiYWJoaXNoZWsgamFkYXYiLCJvcmdfY29kZXMiOlsib3JnXzU4NGUzODRjY2U2Il0sInBpY3R1cmUiOiJodHRwczovL2dyYXZhdGFyLmNvbS9hdmF0YXIvYzU2MzdlYTc3Mzk2ZDNmY2E4OTUxOWIyYTlmYTZiZDA4M2NkMDRmNTEwMDgwNDcwMmJlYWYyNjk4ZTIyMmM5ZT9kPWJsYW5rXHUwMDI2c2l6ZT0yMDAiLCJyYXQiOjE3MjQwNTA3MTcsInN1YiI6ImtwX2ZiMTkxOGJmNzVjNDRmN2JiYzU4ZmZmYjBmOTczYzRkIiwidXBkYXRlZF9hdCI6MS43MjQwNTA3MTdlKzA5fQ.HBqh3HQ1eUosCjEjGdRojN9PvPV2UpYKlhelbIwLGbqFNMGybDj9ssNjrlPJQRvdRN3sBPmJzvxYrXIqo5x20XOOr6IFWSYdt0xxg7QdzwuxVE6XeYRkDWWWoxThX6-paJ2oP8WyHprBePwnfLicLcOVDfWSXMoOGNfxgENbHrEsTm2GmPYGy-kF7cQjwL947a0wArM3yTBeEGqU3bVeWqjUP35sYOJIp4KHKuASXQmWywPJiWZ6hFw0jU6wTfyrx_V8EQwN7M7V2BMRjG-E3FDCFaPLoY6tX1EW86nK09HJo7a4HiWVKFF_wjDFVrlnumUECPFoynsPq0_Yy9w0Uw',
    'refresh_token': 'RvM4_R_4GpOktI1q-3EuBCcJqiT7wcs4djpi8EUH3-s.H2XTBruFFNXSRZ1NE5Y5hgQTwdbv559oNSB585GW-sg'
    }

    def process_alerts(alerts):
        risk_levels = {
            "High": {"severity": "S1", "priority": "P1"},
            "Medium": {"severity": "S2", "priority": "P2"},
            "Low": {"severity": "S3", "priority": "P3"}
        }

        processed_alerts = []

        for alert in alerts:
            riskdesc = alert.get("riskdesc", "Low")
            risk_level = risk_levels.get(riskdesc, {"severity": "S3", "priority": "P3"})

            instances = alert.get("instances", [])
            instance_table = """
            <html>
            <div contenteditable="true">
            <table style="border-collapse: collapse; width: 100%;">
                <thead>
                    <tr>
                        <th style="border: 1px solid orange; padding: 8px;">URI</th>
                        <th style="border: 1px solid orange; padding: 8px;">Method</th>
                        <th style="border: 1px solid orange; padding: 8px;">Evidence</th>
                        <th style="border: 1px solid orange; padding: 8px;">Other Info</th>
                    </tr>
                </thead>
                <tbody>
            """
            for instance in instances:
                instance_table += "<tr>"
                instance_table += f"<td style='border: 1px solid orange; padding: 8px;'>{instance.get('uri', 'N/A')}</td>"
                instance_table += f"<td style='border: 1px solid orange; padding: 8px;'>{instance.get('method', 'N/A')}</td>"
                instance_table += f"<td style='border: 1px solid orange; padding: 8px;'>{instance.get('evidence', 'N/A')}</td>"
                instance_table += f"<td style='border: 1px solid orange; padding: 8px;'>{instance.get('otherinfo', 'N/A')}</td>"
                instance_table += "</tr>"
            instance_table += "</tbody></table></div></html>"

            solution = alert.get("solution", "")
            solution_html = f"<p><b>Solution:</b></p><p>{solution}</p>" if solution else ""

            processed_alert = {
                "title": f"Security - {alert.get('alert', 'No Title')}",
                "description": f"Description:{alert.get('desc', 'No Description')}<br><br>Instances:<br>{instance_table}<br><br>{solution_html}",
                "state": "open",
                "assignees": [],
                "labels": [{"title": "Security", "color": "bg-orange-500", "description": "Security Issues", "id": 33}],
                "severity": risk_level["severity"],
                "priority": risk_level["priority"]
            }

            processed_alerts.append(processed_alert)

        return processed_alerts

    def post_defects_to_api(defects):
        for defect in defects:
            response = requests.post(api_endpoint, headers=headers, cookies=cookies, json=defect)
            if response.status_code != 201:
                print(f"Failed to log defect: {response.status_code} - {response.text}")
            else:
                print(f"Defect logged successfully: {response.json()}")

    try:
        with open(f"{report_name}.json", 'r') as f:
            alerts = json.load(f)
            defects = process_alerts(alerts)
            post_defects_to_api(defects)
        return JSONResponse(status_code=200, content={"message": "Defects logged successfully."})
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Report not found.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
### Download Endpoints ###
@app.get("/Download_PDF_Report/")
def download_pdf_file(file_name: str):
    file_name = f"{file_name}.pdf"
    try:
        with open(file_name, "rb") as f:
            file_content = f.read()
        return Response(content=file_content, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename={file_name}"})
    except FileNotFoundError:
        return {"error": "File not found"}

@app.get("/Download_HTML_Report/")
def download_html_file(file_name: str):
    file_name = f"{file_name}.html"
    try:
        with open(file_name, "rb") as f:
            file_content = f.read()
        return Response(content=file_content, media_type="text/html", headers={"Content-Disposition": f"attachment; filename={file_name}"})
    except FileNotFoundError:
        return {"error": "File not found"}

@app.get("/Download_JSON_Report/")
def download_JSON_file(file_name: str):
    file_name = f"{file_name}.json"
    try:
        with open(file_name, "rb") as f:
            file_content = f.read()
        return Response(content=file_content, media_type="application/json", headers={"Content-Disposition": f"attachment; filename={file_name}"})
    except FileNotFoundError:
        return {"error": "File not found"}
    
app.include_router(router)
