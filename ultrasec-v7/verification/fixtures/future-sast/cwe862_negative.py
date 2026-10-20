from rest_framework.decorators import permission_classes
from rest_framework.permissions import IsAuthenticated

@permission_classes([IsAuthenticated])
def sensitive_endpoint(request):
    return perform_admin_operation(request)
