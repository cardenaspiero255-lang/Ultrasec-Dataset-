from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def submit(request):
    return handle(request)
