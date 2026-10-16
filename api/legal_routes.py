"""
Legal and Compliance Routes
===========================
Serves bilingual (Arabic & English) Privacy Policy and Terms of Service pages
required for Google OAuth 2.0 Verification, Google Play Console, and COPPA/GDPR compliance.
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["Legal & Compliance"])


PRIVACY_POLICY_HTML = """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>سياسة الخصوصية | FinFamily Privacy Policy</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800;900&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #0F2D52;
            --primary-dark: #0A1E38;
            --emerald: #00B894;
            --emerald-dark: #00997B;
            --coral: #FF7675;
            --bg: #F8FAFC;
            --card-bg: #FFFFFF;
            --text-primary: #1E293B;
            --text-secondary: #64748B;
            --border: #E2E8F0;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Cairo', 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background-color: var(--bg);
            color: var(--text-primary);
            line-height: 1.8;
            padding: 0;
            margin: 0;
        }

        header {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: #FFFFFF;
            padding: 50px 20px;
            text-align: center;
            box-shadow: 0 4px 20px rgba(15, 45, 82, 0.15);
        }

        .header-content {
            max-width: 900px;
            margin: 0 auto;
        }

        .logo-badge {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            background: rgba(255, 255, 255, 0.12);
            padding: 8px 18px;
            border-radius: 999px;
            font-size: 15px;
            font-weight: 700;
            margin-bottom: 20px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.15);
        }

        h1 {
            font-size: 36px;
            font-weight: 900;
            margin-bottom: 12px;
            letter-spacing: -0.5px;
        }

        .last-updated {
            font-size: 14px;
            color: #CBD5E1;
        }

        .lang-switch-container {
            display: flex;
            justify-content: center;
            gap: 12px;
            margin-top: 24px;
        }

        .lang-btn {
            background: rgba(255, 255, 255, 0.2);
            color: white;
            border: none;
            padding: 8px 20px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .lang-btn.active, .lang-btn:hover {
            background: var(--emerald);
            color: white;
        }

        main {
            max-width: 900px;
            margin: 40px auto;
            padding: 0 20px;
        }

        .card {
            background: var(--card-bg);
            border-radius: 18px;
            padding: 35px 30px;
            margin-bottom: 25px;
            border: 1px solid var(--border);
            box-shadow: 0 2px 12px rgba(0, 0, 0, 0.03);
        }

        h2 {
            font-size: 22px;
            font-weight: 800;
            color: var(--primary);
            margin-bottom: 18px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        h2 span.icon {
            font-size: 24px;
        }

        p, ul, ol {
            font-size: 16px;
            color: var(--text-primary);
            margin-bottom: 15px;
        }

        ul, ol {
            padding-right: 25px;
        }

        li {
            margin-bottom: 8px;
        }

        .highlight-box {
            background: #F0FDF4;
            border-right: 4px solid var(--emerald);
            padding: 16px 20px;
            border-radius: 10px;
            margin: 20px 0;
            font-size: 15px;
        }

        .contact-box {
            background: #EFF6FF;
            border-right: 4px solid #3B82F6;
            padding: 20px;
            border-radius: 12px;
            margin-top: 25px;
        }

        footer {
            text-align: center;
            padding: 40px 20px;
            font-size: 14px;
            color: var(--text-secondary);
            border-top: 1px solid var(--border);
            background: #FFFFFF;
            margin-top: 50px;
        }

        a {
            color: var(--emerald-dark);
            text-decoration: none;
            font-weight: 600;
        }

        a:hover {
            text-decoration: underline;
        }

        .en-content {
            display: none;
            text-align: left;
            direction: ltr;
        }

        .en-content ul, .en-content ol {
            padding-left: 25px;
            padding-right: 0;
        }

        .en-content .highlight-box {
            border-right: none;
            border-left: 4px solid var(--emerald);
        }

        .en-content .contact-box {
            border-right: none;
            border-left: 4px solid #3B82F6;
        }
    </style>
</head>
<body>

<header>
    <div class="header-content">
        <div class="logo-badge">👨‍👩‍👧‍👦 FinFamily</div>
        <h1 id="title-text">سياسة الخصوصية وحماية البيانات</h1>
        <p class="last-updated" id="updated-text">آخر تحديث: 16 أكتوبر 2026 | الإصدار 1.1.0</p>
        <div class="lang-switch-container">
            <button class="lang-btn active" onclick="switchLang('ar')">العربية</button>
            <button class="lang-btn" onclick="switchLang('en')">English</button>
        </div>
    </div>
</header>

<main>

    <!-- ARABIC CONTENT -->
    <div id="ar-section" class="ar-content">
        <div class="card">
            <h2><span class="icon">🛡️</span> 1. مقدمة والتزامنا بالخصوصية</h2>
            <p>
                أهلاً بكم في <strong>FinFamily</strong>، المنصة المالية العائلية الرائدة المصممة لتمكين الآباء والأبناء من إدارة المصروف والادخار واكتساب الثقافة المالية بأمان. نحن نلتزم التزاماً صارماً بحماية خصوصية كافة المستخدمين وخاصة الأطفال، ونراعي المعايير الدولية واللوائح المصرفية الرقمية المنظمة لمعاملات الأسرة.
            </p>
            <div class="highlight-box">
                <strong>تعهد أمان مطلق:</strong> نحن لا نبيع، ولا نؤجر، ولا نتاجر ببيانات المستخدمين أو حسابات Google أو بيانات المعاملات المالية مع أي طرف ثالث أو شبكات إعلانية بأي شكل من الأشكال.
            </div>
        </div>

        <div class="card">
            <h2><span class="icon">🔑</span> 2. البيانات التي نجمعها</h2>
            <p>نقوم بجمع البيانات الضرورية فقط لتشغيل المنصة وتقديم خدماتها بكفاءة وأمان:</p>
            <ul>
                <li><strong>بيانات تسجيل الدخول عبر Google (Google OAuth Data):</strong>
                    عند اختياركم تسجيل الدخول عبر Google، نقوم باستلام بيانات الحساب الأساسية المصرح بها من طرفكم فقط وتشمل: (الاسم الكامل، عنوان البريد الإلكتروني، معرف المستخدم الفريد من Google، والصورة الشخصية). لا نطلب ولا نصل إطلاقاً لكلمات مرور Google أو أي ملفات أخرى في حسابكم.
                </li>
                <li><strong>بيانات حسابات أولياء الأمور:</strong>
                    الاسم الكامل، البريد الإلكتروني، كلمة المرور المشفرة (بصيغة Bcrypt غير قابلة للاسترجاع)، وإعدادات التحقق بخطوتين (2FA).
                </li>
                <li><strong>بيانات حسابات الأبناء:</strong>
                    الاسم الأول، رمز PIN المشفر للدخول، المستوى المالي، رصيد نقاط الخبرة (XP)، والمهام المنجزة. تنشأ حسابات الأبناء بإشراف وموافقة ولي الأمر الكاملة.
                </li>
                <li><strong>بيانات المعاملات المالية والمحفظة:</strong>
                    سجل المصروف الأسبوعي أو الفوري، أهداف الادخار، حدود الصرف اليومية والشهرية، وسجل مشتريات بطاقة ميزة المحاكاة.
                </li>
            </ul>
        </div>

        <div class="card">
            <h2><span class="icon">👶</span> 3. حماية خصوصية الأطفال (COPPA Compliance)</h2>
            <p>
                نظراً لأن منصة FinFamily مصممة للأسر والأطفال، فإننا نولي خصوصية القاصرين أعلى درجات العناية:
            </p>
            <ul>
                <li>لا يمكن لأي طفل إنشاء حساب بصورة مستقلة، بل يتم إنشاء وإدارة الحساب حصرياً من قِبل ولي الأمر المصرح له.</li>
                <li>لا نجمع من الأطفال أي بيانات موقع جغرافي، ولا نتيح أي غرف دردشة عامة أو تواصل مع غرباء.</li>
                <li>يمتلك ولي الأمر التحكم والوصول الكامل لمراجعة كافة بيانات وسجلات طفله أو تعديلها أو حذفها في أي لحظة.</li>
            </ul>
        </div>

        <div class="card">
            <h2><span class="icon">🔒</span> 4. كيفية حماية البيانات وعزل العائلات</h2>
            <p>
                نطبق معايير أمنية متقدمة لضمان سرية وسلامة البيانات:
            </p>
            <ul>
                <li><strong>العزل التام بين العائلات (Family Isolation Policy):</strong> يتم عزل بيانات كل أسرة منطقياً وقاعدياً، ولا يمكن بأي حال لأي ولي أمر أو طفل الاطلاع على محافظ أو مهام أو مشتريات أسرة أخرى.</li>
                <li><strong>التشفير الكامل أثناء النقل والتخزين:</strong> كافة الاتصالات بين التطبيق والخوادم مشفرة ببروتوكول HTTPS / TLS 1.3 مع حماية الرموز عبر JWT Tokens المشفرة وشهادات موثقة.</li>
                <li><strong>تخزين آمن محلياً:</strong> يستخدم تطبيق الموبايل تقنيات التخزين المشفر لنظام Android (EncryptedSharedPreferences) لحفظ الجلسة بأمان.</li>
            </ul>
        </div>

        <div class="card">
            <h2><span class="icon">🗑️</span> 5. حذف الحساب والبيانات (Data Deletion)</h2>
            <p>
                يحق لأي ولي أمر في أي وقت طلب حذف حسابه وجميع بيانات عائلته وأطفاله نهائياً من خوادمنا:
            </p>
            <ul>
                <li>يمكن تقديم طلب الحذف المباشر عبر إرسال بريد إلكتروني إلى فريق الدعم الفني: <a href="mailto:modyhashim2006@gmail.com">modyhashim2006@gmail.com</a>.</li>
                <li>يتم حذف كافة السجلات والمعاملات وبيانات الحساب بصورة نهائية وغير قابلة للاسترجاع خلال 48 ساعة من تأكيد الطلب.</li>
            </ul>
        </div>

        <div class="card contact-box">
            <h2><span class="icon">📞</span> 6. اتصل بنا</h2>
            <p>إذا كانت لديكم أي استفسارات أو ملاحظات بخصوص سياسة الخصوصية وحماية البيانات، يسعدنا تواصلكم المباشر معنا:</p>
            <p><strong>البريد الإلكتروني للدعم الفني:</strong> <a href="mailto:modyhashim2006@gmail.com">modyhashim2006@gmail.com</a></p>
            <p><strong>مشروع FinFamily — مبادرة FinYology المصرفية 2026</strong></p>
        </div>
    </div>

    <!-- ENGLISH CONTENT -->
    <div id="en-section" class="en-content">
        <div class="card">
            <h2><span class="icon">🛡️</span> 1. Introduction & Privacy Commitment</h2>
            <p>
                Welcome to <strong>FinFamily</strong>, the comprehensive family financial literacy platform designed to empower parents and children to safely manage allowances, establish savings goals, and build financial habits. We strictly adhere to global privacy frameworks and digital banking security guidelines to safeguard your household data.
            </p>
            <div class="highlight-box">
                <strong>Our Absolute Privacy Pledge:</strong> We do not sell, rent, monetize, or trade any user data, Google profile credentials, or family financial transactions with any third parties, advertisers, or data brokers under any circumstances.
            </div>
        </div>

        <div class="card">
            <h2><span class="icon">🔑</span> 2. Information We Collect</h2>
            <p>We only collect information strictly necessary to provide and secure FinFamily core services:</p>
            <ul>
                <li><strong>Google Sign-In Account Data:</strong>
                    When you choose to authenticate via Google Sign-In, we receive the basic user claims authorized by your consent: full name, email address, unique Google subject identifier (`sub`), and profile picture URL. We never access your Google password or external Google Drive/files.
                </li>
                <li><strong>Parent Account Information:</strong>
                    Full name, email address, cryptographically hashed passwords (Bcrypt), and two-factor authentication (2FA) verification settings.
                </li>
                <li><strong>Child Profile Information:</strong>
                    First name, hashed 4-6 digit login PIN, gamification XP, level progression, and mission completion records. Child accounts are created and supervised exclusively by their registered parent.
                </li>
                <li><strong>Financial Simulation & Ledger Data:</strong>
                    Allowance transactions, savings goal targets and balances, daily/monthly spending constraints, and simulated Meeza card authorization logs.
                </li>
            </ul>
        </div>

        <div class="card">
            <h2><span class="icon">👶</span> 3. Children's Privacy (COPPA Compliance)</h2>
            <p>
                FinFamily is built from the ground up to protect children's online safety and privacy:
            </p>
            <ul>
                <li>Children cannot register independently; accounts are provisioned exclusively under verified parental authority.</li>
                <li>We do not collect physical geolocation data from children, nor do we provide public chat or social networking vectors.</li>
                <li>Parents maintain continuous oversight and may review, modify, or permanently purge their child's records at any time.</li>
            </ul>
        </div>

        <div class="card">
            <h2><span class="icon">🔒</span> 4. Security & Multi-Family Isolation</h2>
            <p>
                We enforce multi-tiered architectural security measures:
            </p>
            <ul>
                <li><strong>Strict Family Isolation Policies:</strong> Each family operates in an isolated data partition. Foreign UUID lookup or cross-family access is categorically rejected with fail-closed security.</li>
                <li><strong>Encryption in Transit and Rest:</strong> All network communication is safeguarded with TLS 1.3 / HTTPS. Session tokens are digitally signed with secure HMAC SHA-256 JWT keys.</li>
                <li><strong>Android Secure Storage:</strong> The mobile client leverages hardware-backed Android KeyStore and EncryptedSharedPreferences for resilient session persistence.</li>
            </ul>
        </div>

        <div class="card">
            <h2><span class="icon">🗑️</span> 5. Data Retention & Permanent Deletion</h2>
            <p>
                You retain complete ownership over your household information:
            </p>
            <ul>
                <li>To request complete deletion of your account and all associated family and children records, email our support desk at <a href="mailto:modyhashim2006@gmail.com">modyhashim2006@gmail.com</a>.</li>
                <li>All profile records, wallets, and transaction histories will be permanently wiped from production databases within 48 hours of verification.</li>
            </ul>
        </div>

        <div class="card contact-box">
            <h2><span class="icon">📞</span> 6. Contact Us</h2>
            <p>If you have any questions, inquiries, or security reviews regarding this Privacy Policy, please contact our engineering team directly:</p>
            <p><strong>Support & Privacy Desk:</strong> <a href="mailto:modyhashim2006@gmail.com">modyhashim2006@gmail.com</a></p>
            <p><strong>FinFamily Platform — FinYology Banking Initiative 2026</strong></p>
        </div>
    </div>

</main>

<footer>
    <p>&copy; 2026 FinFamily. All rights reserved. | <a href="/terms">Terms of Service (شروط الاستخدام)</a></p>
</footer>

<script>
    function switchLang(lang) {
        const arSec = document.getElementById('ar-section');
        const enSec = document.getElementById('en-section');
        const titleText = document.getElementById('title-text');
        const updatedText = document.getElementById('updated-text');
        const buttons = document.querySelectorAll('.lang-btn');

        buttons.forEach(b => b.classList.remove('active'));

        if (lang === 'en') {
            document.documentElement.setAttribute('lang', 'en');
            document.documentElement.setAttribute('dir', 'ltr');
            arSec.style.display = 'none';
            enSec.style.display = 'block';
            titleText.innerText = 'FinFamily Privacy Policy & Data Protection';
            updatedText.innerText = 'Last Updated: October 16, 2026 | Version 1.1.0';
            buttons[1].classList.add('active');
        } else {
            document.documentElement.setAttribute('lang', 'ar');
            document.documentElement.setAttribute('dir', 'rtl');
            arSec.style.display = 'block';
            enSec.style.display = 'none';
            titleText.innerText = 'سياسة الخصوصية وحماية البيانات';
            updatedText.innerText = 'آخر تحديث: 16 أكتوبر 2026 | الإصدار 1.1.0';
            buttons[0].classList.add('active');
        }
    }
</script>

</body>
</html>
"""

TERMS_OF_SERVICE_HTML = """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>شروط الخدمة والاستخدام | FinFamily Terms of Service</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800;900&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #0F2D52;
            --primary-dark: #0A1E38;
            --emerald: #00B894;
            --emerald-dark: #00997B;
            --bg: #F8FAFC;
            --card-bg: #FFFFFF;
            --text-primary: #1E293B;
            --text-secondary: #64748B;
            --border: #E2E8F0;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Cairo', 'Inter', sans-serif;
            background-color: var(--bg);
            color: var(--text-primary);
            line-height: 1.8;
        }
        header {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: #FFFFFF;
            padding: 50px 20px;
            text-align: center;
        }
        .header-content { max-width: 900px; margin: 0 auto; }
        h1 { font-size: 34px; font-weight: 900; margin-bottom: 10px; }
        .last-updated { font-size: 14px; color: #CBD5E1; }
        main { max-width: 900px; margin: 40px auto; padding: 0 20px; }
        .card {
            background: var(--card-bg);
            border-radius: 18px;
            padding: 35px 30px;
            margin-bottom: 25px;
            border: 1px solid var(--border);
            box-shadow: 0 2px 12px rgba(0, 0, 0, 0.03);
        }
        h2 { font-size: 20px; font-weight: 800; color: var(--primary); margin-bottom: 15px; }
        p, ul { font-size: 16px; margin-bottom: 15px; }
        ul { padding-right: 25px; }
        li { margin-bottom: 8px; }
        footer {
            text-align: center;
            padding: 40px 20px;
            font-size: 14px;
            color: var(--text-secondary);
            border-top: 1px solid var(--border);
            background: #FFFFFF;
            margin-top: 50px;
        }
        a { color: var(--emerald-dark); text-decoration: none; font-weight: 600; }
    </style>
</head>
<body>

<header>
    <div class="header-content">
        <h1>شروط وأحكام الخدمة (Terms of Service)</h1>
        <p class="last-updated">آخر تحديث: 16 أكتوبر 2026 | FinFamily Platform</p>
    </div>
</header>

<main>
    <div class="card">
        <h2>1. قبول الشروط</h2>
        <p>
            باستخدامكم لتطبيق ومنصة <strong>FinFamily</strong>، فإنكم توافقون على الالتزام بشروط الخدمة هذه وكافة القوانين المعمول بها. هذه المنصة مخصصة للأغراض التعليمية والتدريب المالي الأسري الخاضع لإشراف الوالدين.
        </p>
    </div>

    <div class="card">
        <h2>2. مسؤوليات ولي الأمر</h2>
        <p>
            يتحمل ولي الأمر المسؤولية الكاملة عن إنشاء حسابات الأبناء التابعة لعائلته، وتحديد حدود الصرف المالي، والموافقة على العمليات والمهام.
        </p>
    </div>

    <div class="card">
        <h2>3. طبيعة الخدمات المالية والمحاكاة</h2>
        <p>
            المعاملات والبطاقات التفاعلية داخل التطبيق تهدف إلى تدريب النشء على التوفير وإدارة الميزانية. أي خدمات ربط بنكي حقيقية تخضع لمعايير الرقابة المصرفية المعتمدة لدى البنك المركزي المصري.
        </p>
    </div>

    <div class="card">
        <h2>4. الحسابات والأمان</h2>
        <p>
            يلتزم المستخدم بالحفاظ على سرية كلمة المرور ورمز PIN وبيانات تسجيل الدخول عبر Google، وإبلاغ الدعم الفني فور الاشتباه في أي وصول غير مصرح به.
        </p>
    </div>

    <div class="card">
        <h2>5. التواصل والدعم</h2>
        <p>للاستفسارات القانونية والتنظيمية: <a href="mailto:modyhashim2006@gmail.com">modyhashim2006@gmail.com</a></p>
    </div>
</main>

<footer>
    <p>&copy; 2026 FinFamily. All rights reserved. | <a href="/privacy">Privacy Policy (سياسة الخصوصية)</a></p>
</footer>

</body>
</html>
"""


@router.get("/privacy", response_class=HTMLResponse)
@router.get("/api/privacy", response_class=HTMLResponse)
def get_privacy_policy():
    """Returns official bilingual Privacy Policy HTML."""
    return HTMLResponse(content=PRIVACY_POLICY_HTML, status_code=200)


@router.get("/terms", response_class=HTMLResponse)
@router.get("/api/terms", response_class=HTMLResponse)
def get_terms_of_service():
    """Returns official Terms of Service HTML."""
    return HTMLResponse(content=TERMS_OF_SERVICE_HTML, status_code=200)
