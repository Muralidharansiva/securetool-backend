import json, socket, requests
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import ScanResult
from .utils import scan_port
from accounts.views import can_scan


@login_required
def security_check(request):
    if not can_scan(request.user):
        return JsonResponse({"error": "Daily limit exceeded"}, status=403)

    url = request.GET.get("url")
    if not url:
        return JsonResponse({"error": "URL required"}, status=400)

    if not url.startswith("http"):
        url = "https://" + url

    r = requests.get(url, timeout=5)
    score = 100
    issues = []

    headers = r.headers
    required = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ]

    for h in required:
        if h not in headers:
            issues.append(f"Missing {h}")
            score -= 10

    ScanResult.objects.create(
        url=url,
        ip="N/A",
        open_ports="",
        risk_score=score
    )

    return JsonResponse({
        "score": score,
        "issues": issues
    })


@login_required
def port_scan(request):
    if not can_scan(request.user):
        return JsonResponse({"error": "Daily limit exceeded"}, status=403)

    data = json.loads(request.body)
    host = data.get("host")

    ip = socket.gethostbyname(host)
    open_ports = []

    for port in range(1, 1025):
        if scan_port(ip, port):
            open_ports.append(port)

    ScanResult.objects.create(
        url=host,
        ip=ip,
        open_ports=",".join(map(str, open_ports)),
        risk_score=max(100 - len(open_ports) * 5, 0)
    )

    return JsonResponse({
        "ip": ip,
        "open_ports": open_ports
    })
