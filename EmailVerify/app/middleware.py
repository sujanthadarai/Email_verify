from django.shortcuts import redirect
def guest(view_function):
    def wrapped_view(request,*args,**kwargs):
        if request.user.is_authenticated:
            return redirect('home')
        return view_function(request, *args, **kwargs)
    return wrapped_view