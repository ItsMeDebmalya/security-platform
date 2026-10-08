"""Django with DEBUG=True: the lab's real technical-404 page. Lab only."""

import sys

from django.conf import settings
from django.http import HttpResponse
from django.urls import path

settings.configure(
    DEBUG=True,
    ALLOWED_HOSTS=["*"],
    ROOT_URLCONF=__name__,
    SECRET_KEY="web-lab-only-not-a-secret",
    MIDDLEWARE=[],
)


def index(request):
    return HttpResponse(
        "<!doctype html><html><head><title>django lab</title></head><body><p>ok</p></body></html>"
    )


urlpatterns = [path("", index)]

if __name__ == "__main__":
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
