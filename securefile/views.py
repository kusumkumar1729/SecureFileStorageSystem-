from django.shortcuts import render, redirect, HttpResponse
from django.http import JsonResponse
from django.core.mail import send_mail
import random
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from django.conf import settings
from .models import Profile  # Import Profile model

def index(request):
    return render(request, 'index.html')

def register(request):
    if request.method == "POST":
        action = request.POST.get("action")

        if action == "register":
            username = request.POST.get("username").strip()
            email = request.POST.get("email").strip()
            password = request.POST.get("password")
            confirm_password = request.POST.get("confirm_password")

            if not username or not email or not password or not confirm_password:
                return JsonResponse({"status": "error", "message": "All fields are required!"})

            if password != confirm_password:
                return JsonResponse({"status": "error", "message": "Passwords do not match!"})

            if User.objects.filter(username=username).exists():
                return JsonResponse({"status": "error", "message": "Username already taken! Please choose another."})

            if User.objects.filter(email=email).exists():
                return JsonResponse({"status": "error", "message": "Email already registered!"})

            otp = random.randint(100000, 999999)
            request.session['otp'] = otp
            request.session['email'] = email
            request.session['password'] = password
            request.session['username'] = username
            request.session.modified = True  

            print(f"Debug - Generated OTP: {otp} for {email}")  

            try:
                send_mail(
                    "Your OTP Code",
                    f"Your OTP for registration is {otp}",
                    settings.EMAIL_HOST_USER,
                    [email],
                    fail_silently=False,
                )
                return JsonResponse({"status": "success", "message": "OTP sent successfully!"})

            except Exception as e:
                print(f"Email sending error: {e}")
                return JsonResponse({"status": "error", "message": "Failed to send OTP. Please try again later."})

    return render(request, "register.html")

def verify_otp(request):
    if request.method == "POST":
        entered_otp = request.POST.get("email_otp")
        stored_otp = request.session.get('otp')
        email = request.session.get('email')
        password = request.session.get('password')
        username = request.session.get('username')

        if not username or not email or not password:
            return JsonResponse({"status": "error", "message": "Session expired! Please register again."})

        if str(entered_otp) == str(stored_otp):
            try:
                user = User.objects.create_user(username=username, email=email, password=password)
                user.save()

                Profile.objects.create(user=user, id_user=user.id)

                # Clear session data
                request.session.flush()

                return redirect('success')

            except Exception as e:
                print(f"Error creating user: {e}")
                return JsonResponse({"status": "error", "message": "Error creating account. Please try again."})

        return JsonResponse({"status": "error", "message": "Invalid OTP!"})

    return redirect('register')

@csrf_protect
def signin(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('dashboard', username=user.username)  # Redirect properly
        else:
            return render(request, "signin.html", {'error': 'Invalid credentials'})

    return render(request, "signin.html")




def signout(request):
    logout(request)
    return redirect("signin")



def get_user_profile(user):
    try:
        return Profile.objects.get(user=user)
    except Profile.DoesNotExist:
        return None



@login_required
def dashboard(request, username):
    # Ensure the logged-in user is accessing their own dashboard
    if request.user.username != username:
        return redirect(f'/dashboard/{request.user.username}/')  # Redirect to correct dashboard

    user_profile = get_user_profile(request.user)

    context = {
        'user': request.user,
        'user_profile': user_profile,
    }
    return render(request, 'dashboard.html', context)



def success(request):
    return render(request,'success.html')
