import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
from dotenv import load_dotenv

load_dotenv()

from db.database import engine, Base
from api.routes import functions_router
from api.auth_routes import router as auth_router
from api.family_routes import router as family_router
from core.limiter import limiter

# بناء الجداول في الداتا بيز بناءً على الـ Models
Base.metadata.create_all(bind=engine)

app = FastAPI(title="FinFamily API")

# Rate limiting — بيحمي بالذات الـ login endpoints من Brute-force
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# إعدادات الـ CORS — دفاع إضافي بس (defense-in-depth)، مش أساسي، لأن في الإنتاج
# الفرونت والباك اند بيبانوا نفس الـ origin للمتصفح (nginx بيعمل proxy لـ /api
# على الباك اند من غير ما المتصفح يعرف). بس بنسيبها configurable لأي استخدام
# تاني (زي حد بيضرب الـ API مباشرة من أداة API tester أو تطبيق موبايل مستقبلاً).
# ALLOWED_ORIGINS في الـ .env: قايمة مفصولة بفواصل، زي:
#   ALLOWED_ORIGINS=http://localhost:5173,https://finfamily.app
allowed_origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# تسجيل الـ Routes
app.include_router(auth_router)
app.include_router(family_router)
app.include_router(functions_router)