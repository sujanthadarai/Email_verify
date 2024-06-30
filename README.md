#Sujan Thadarai
Doc for email verify in django 

STEP1:

set up email with django 
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_USE_TLS = True
EMAIL_PORT = 587
EMAIL_HOST_USER = ''
EMAIL_HOST_PASSWORD =''

-------------------------------------------------------------------
STEP2:
in views.py
from django.core.mail import EmailMessage, send_mail
from EmailVerify import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from . token import generate_token
from .middleware import guest

 OPEN SETTINGS.PY IN MYPROJECT FOLDER
___________________________________________
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
                

______________________________________________________________________
activateion code
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

________________________________________________________________________
token.py
from django.contrib.auth.tokens import PasswordResetTokenGenerator

class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self,user,timestamp):
        return (
        str(user.pk) + str(timestamp) 
        # text_type(user.profile.signup_confirmation)
        )

generate_token = TokenGenerator()
____________________________________________
Emailcomfirmation.html
<!-- templates/auth/account_activation_email.html -->
<p>Hi {{ user.username }},</p>
<p>Please click the link below to activate your account:</p>
<a href="http://{{ domain }}{% url 'activate' uidb64=uid token=token %}">Activate your account</a>

<!-- templates/auth/account_activation_invalid.html -->
<h2>Activation link is invalid!</h2>
<p>The activation link is invalid. Please try registering again.</p>


______________________________________________________________________




______________________________________________________________

_________________________________________________________________


_________________________________________________________________

____________________________________________________________________

_____________________________________________________

