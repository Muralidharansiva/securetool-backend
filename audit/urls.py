from django.urls import path
from .views import security_check, port_scan

urlpatterns = [
    path("security-check/", security_check),
    path("port-scan/", port_scan),
]
