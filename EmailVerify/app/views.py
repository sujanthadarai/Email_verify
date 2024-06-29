
from django.shortcuts import render,redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,login,logout,update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from django.core.mail import EmailMessage, send_mail
from EmailVerify import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from . token import generate_token
from .middleware import guest


def index(request):
    return render(request,'index.html')


@guest
def register(request):
    if request.method=='POST':
        name=request.POST['name']
        username=request.POST['username']
        email=request.POST['email']
        password=request.POST['password']
        password1=request.POST['password1']
        
        try:
                # Validate password using Django's built-in validators
            validate_password(password)
        
            if password==password1:
                if User.objects.filter(username=username).exists():
                    messages.info(request,"username is already exists!!!")
                    return redirect('register')
                elif User.objects.filter(email=email).exists():
                    messages.info(request,'email  is already exists!!!')
                    return redirect('register')
                
                else:
                    user = User.objects.create_user(first_name=name, username=username, email=email, password=password, is_active=False)
                    # Email Address Confirmation Email
                current_site = get_current_site(request)
                email_subject = "Confirm your Email @  StreamSync !!"
                message2 = render_to_string('email_confirmation.html',{
                    
                    'name': user.first_name,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': generate_token.make_token(user)
                })
                email = EmailMessage(
                email_subject,
                message2,
                settings.EMAIL_HOST_USER,
                [user.email],
                )
                email.fail_silently = True
                email.send()
                
                messages.success(request, 'Register successfully! Please check your email to verify your account.')
                return redirect("log_in")
        except ValidationError as e:
            # If password validation fails, display the error messages
            for error in e.messages:
                messages.error(request, error)
            return redirect('register')
                
        else:
            messages.error(request,"password is not match")
            return redirect('register')
            
    return render(request,'register.html')

@guest
def activate(request,uidb64,token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        user = None

    if user is not None and generate_token.check_token(user,token):
        user.is_active = True
        # user.profile.signup_confirmation = True
        user.save()
        login(request,user,backend='myapp.backends.MyBackend')
        messages.success(request, "Your Account has been activated!!")
        return redirect('log_in')
    else:
        return render(request,'activation_invalid.html')

@guest
def log_in(request):
    if request.method=='POST':
        username=request.POST['username']
        password=request.POST['password']
        
        if not User.objects.filter(username=username).exists():
            messages.info(request,"username is not register yet!!!")
            return redirect('log_in')
        
        user=authenticate(username=username,password=password)
        if user is not None:
            login(request,user)
            return redirect("index")
        else:
            messages.error(request,"invalid keyword!!!")
            return redirect("log_in")
             
    return render(request,'login.html')

def log_out(request):
    logout(request)
    return redirect('log_in')