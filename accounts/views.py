import json, random
from django.http import JsonResponse
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.utils import timezone
from .models import OTP, DailyScanLimit
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def register(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)

    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"error": "Invalid JSON format"}, status=400)

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return JsonResponse({"error": "Missing fields"}, status=400)

    if User.objects.filter(username=username).exists():
        return JsonResponse({"error": "User already exists"}, status=400)

    User.objects.create_user(username=username, password=password)
    return JsonResponse({"status": "registered"})


@csrf_exempt
def user_login(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)

    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"error": "Invalid JSON format"}, status=400)

    user = authenticate(
        username=data.get("username"),
        password=data.get("password")
    )

    if user is None:
        return JsonResponse({"error": "Invalid credentials"}, status=401)

    login(request, user)
    return JsonResponse({
        "status": "logged_in",
        "is_admin": user.is_staff
    })

# ---------- ADMIN OTP ----------
def admin_send_otp(request):
    data = json.loads(request.body)
    code = str(random.randint(100000, 999999))
    OTP.objects.create(email=data["email"], code=code)
    return JsonResponse({"otp": code})  # demo only

def admin_verify_otp(request):
    data = json.loads(request.body)
    otp = OTP.objects.filter(email=data["email"]).last()
    if otp and otp.code == data["code"]:
        user, _ = User.objects.get_or_create(
            username=data["email"],
            is_staff=True
        )
        user.is_staff = True
        user.save()
        login(request, user)
        return JsonResponse({"status": "admin_logged"})
    return JsonResponse({"error": "invalid otp"}, status=400)

# ---------- SCAN LIMIT ----------
def can_scan(user):
    if user.is_staff:
        return True
    today = timezone.now().date()
    rec, _ = DailyScanLimit.objects.get_or_create(user=user, date=today)
    if rec.count >= 2:
        return False
    rec.count += 1
    rec.save()
    return True
