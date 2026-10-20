from django.views.decorators.csrf import csrf_protect

@csrf_protect
def submit(request):
    return handle(request)
