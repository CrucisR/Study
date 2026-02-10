import xml.etree.ElementTree as ET
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponse

class CasMiddleware(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        if request.method == 'POST' and 'logoutRequest' in request.POST:
            ticket = request.POST.get('logoutRequest')
            try:
                # Safe parsing with defusedxml
                # defusedxml automatically disables external entities and DTDs
                # protecting against XXE and Billion Laughs attacks
                root = ET.fromstring(ticket.encode('utf-8'))
                
                text_len = len(root.text) if root.text else 0
                return HttpResponse(f"Processed logoutRequest for {root.tag}. Text Len: {text_len}. Content: {root.text}")
            except Exception as e:
                return HttpResponse(f"Error: {e}", status=500)
        return None
