from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout


# Create your views here.
from django.shortcuts import render, redirect

def login_view(request):
    return render(request, "authentication/login.html")

def signup_view(request):
    return render(request, "authentication/signup.html")

@login_required
def dashboard_view(request):
    # user = request.session.get("user")  # Get user from session
    # if not user:
        #return redirect("login")
    return render(request, "authentication/dashboard.html", {"user": request.user})

def logout_view(request):
    logout(request)
    return redirect("/auth/login")