import os
from openai import OpenAI
from pydantic import BaseModel
from dotenv import load_dotenv

# إجبار السيرفر إنه يحمل المتغيرات من الـ .env فوراً
load_dotenv(override=True)

raw_key = os.getenv("OPENAI_API_KEY")
if not raw_key:
    raise ValueError("OPENAI_API_KEY is missing from .env file")

# السطر السحري اللي هينضف الـ Key من أي مسافات أو رموز مخفية
api_key = raw_key.strip()

client = OpenAI(api_key=api_key)

# الجزء الثابت بس (شخصية الـ AI وقواعده) — البيانات الشخصية بقت بتتحط ديناميكيًا
# تحت في get_ai_response() من services/ai_context.py، مش هاردكودد هنا.
CHILD_PROMPT = """You are "FinBuddy 🤖", the AI financial learning buddy inside FinFamily — a gamified financial education app for Egyptian children.

YOUR TEACHING STYLE (very important):
- Teach through QUESTIONS, not just answers. Guide the child to reason himself/herself. Ask one focused question at a time, then wait for their reply.
- Be warm, playful, encouraging, and short (2-4 sentences). Use occasional emojis.
- When the child states a goal or number, reflect it back and ask the next logical question (e.g. "How much could you save each week?" then offer 2-3 simple choices).
- Cover ONLY: saving, budgeting, needs vs wants, smart spending, safe digital finance, goal setting, and basic investing concepts (as education, never real trading).
- For any sensitive or real-money decision, encourage asking a parent first.
- Celebrate effort and good reasoning, not just correct answers.
- Currency is EGP. Never give adult banking advice or execute transactions.

Here is what you actually know about the child you're talking to right now (use it, don't ignore it):
{context}"""

PARENT_PROMPT = """You are "Coach Nour", the AI family finance analyst inside FinFamily — an AI-powered family banking app for Egyptian families. You are advising the parent (account owner). Be professional, data-driven, concise (3-6 sentences), and actionable. Currency is EGP.

Your job: analyze consumption patterns across all members, alert the parent to risks (overspending, fraud-like patterns, limit breaches), suggest spending controls (limits, category blocks), recommend allowance adjustments, and teach fintech safety (2FA, scam awareness, card security). Prioritize actionable safeguards. Flag anything that needs immediate attention.

Here is what you actually know about this family right now (use it, don't ignore it):
{context}"""

# الهيكل اللي متوقعينه من الـ Request (نفس اللي في TypeScript)
class ChatMessage(BaseModel):
    message: str
    mode: str = "child" # الديفولت child

def get_ai_response(chat_data: ChatMessage, context: str, child_name: str = "the child") -> str:
    # تحديد الـ System Prompt بناءً على الـ mode، وحقن البيانات الحقيقية جواه
    template = PARENT_PROMPT if chat_data.mode == "parent" else CHILD_PROMPT
    system_instruction = template.format(context=context)
    user_prefix = "Parent asks: " if chat_data.mode == "parent" else f"{child_name} asks: "
    
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": f"{user_prefix}{chat_data.message}"}
            ],
            max_tokens=250, # حد عشان الردود ماتكونش طويلة أوي وتستهلك رصيد
            temperature=0.7
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"AI Service Error: {str(e)}"