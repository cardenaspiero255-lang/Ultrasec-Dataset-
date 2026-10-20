from rest_framework.decorators import permission_classes
from rest_framework.permissions import AllowAny

@permission_classes([AllowAny])
def sensitive_endpoint(request):
    return perform_admin_operation(request)
