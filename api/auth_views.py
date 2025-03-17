import os
from google_auth_oauthlib.flow import Flow
from django.http import JsonResponse
from django.shortcuts import redirect
from django.contrib.auth import login
from django.contrib.auth.models import User
import requests

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

# Step 1: Start Authentication Flow
def google_auth_start(request):
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uris": [GOOGLE_REDIRECT_URI],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token"
            }
        },
        scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile'],
    )
    flow.redirect_uri = GOOGLE_REDIRECT_URI

    auth_url, _ = flow.authorization_url(prompt="consent")
    return redirect(auth_url)
    #return JsonResponse({"auth_url": auth_url})
    
def google_auth_callback(request):
    code = request.GET.get("code")
    
    if not code:
        return JsonResponse({"error": "Authorization code not found"}, status=400)

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uris": [GOOGLE_REDIRECT_URI],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token"
            }
        },
        scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile'],
    )
    flow.redirect_uri = GOOGLE_REDIRECT_URI
    try:
        flow.fetch_token(code=code, redirect = GOOGLE_REDIRECT_URI)
    except Exception as e:
        return JsonResponse({'error': str(e)},status = 400)
    
    credentials = flow.credentials

    # Fetch user info from Google
    user_info = requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {credentials.token}"}
    ).json()

    email = user_info.get("email")
    name = user_info.get("name")

    # Check if user exists, if not, create a new user
    user, created = User.objects.get_or_create(username=email, defaults={"email": email, "first_name": name})

    # Log in the user
    login(request, user)

    # Redirect to dashboard
    return redirect("/auth/dashboard/")
