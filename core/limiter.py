from slowapi import Limiter
from slowapi.util import get_remote_address

# Rate limiting بيعتمد على IP الطلب (get_remote_address).
# لو السيرفر بتاعكم شغال ورا Load Balancer/Reverse Proxy (Nginx, ALB, إلخ)
# لازم تتأكدوا إن الـ Proxy ده بيبعت X-Forwarded-For صح، وإلا كل الطلبات
# هتظهر جاية من نفس IP (IP بتاع الـ Proxy) وده هيبوظ الحساب.
limiter = Limiter(key_func=get_remote_address)