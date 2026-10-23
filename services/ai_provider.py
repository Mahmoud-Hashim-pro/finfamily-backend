"""
services/ai_provider.py - AI Provider Architecture for FinFamily.

Defines:
- AIProvider: Abstract base class for AI completion providers.
- OpenAIProvider: Production OpenAI provider with strict timeouts, semaphore concurrency throttling,
  max_retries=0, and structured exception handling.
- MockAIProvider: Hermetic provider for unit and regression testing without network or API keys.
"""

from abc import ABC, abstractmethod
import logging
import threading
from typing import List, Dict, Any, Optional, Callable
import httpx
from openai import (
    OpenAI,
    OpenAIError,
    APITimeoutError,
    RateLimitError,
    APIConnectionError,
    AuthenticationError,
)

logger = logging.getLogger(__name__)

# BUG-018: Strict 10s provider budget (2s connect + 8s read) and bounded concurrency for OpenAI calls.
AI_PROVIDER_TIMEOUT = httpx.Timeout(8.0, connect=2.0)
AI_SEMAPHORE_WAIT_SECONDS = 2.0
AI_CONCURRENCY_LIMIT = 10


def get_arabic_fallback(reason: str, mode: str = "child") -> str:
    """Return friendly Arabic/English fallback messages based on failure reason and caller mode."""
    if reason in ("provider_not_configured", "not_configured", "auth_error"):
        if mode == "parent":
            return "عذراً، يواجه المستشار المالي صعوبة مؤقتة في الاتصال. يرجى المحاولة بعد قليل."
        return "أهلاً بك يا بطل! 🤖 صديقك الذكي FinBuddy في استراحة قصيرة وسيعود إليك قريباً جداً!"
    elif reason in ("timeout", "timeout_error"):
        if mode == "parent":
            return "عذراً، استغرقت الخدمة وقتاً أطول من المتوقع للرد. يُرجى المحاولة مرة أخرى لاحقاً."
        return "عذراً يا بطل! ⏱️ استغرق الرد وقتاً أطول من المعتاد. حاول أن تسألني مرة ثانية بعد قليل!"
    elif reason in ("rate_limited", "concurrency_limit"):
        if mode == "parent":
            return "تم الوصول للحد الأقصى للطلبات حالياً. يُرجى الانتظار دقيقة والمحاولة مجدداً."
        return "أنت ذكي ونشيط جداً يا بطل! 🌟 انتظر لحظات قليلة ودعنا نواصل التعلم معاً."
    elif reason == "connection_error":
        if mode == "parent":
            return "عذراً، يواجه المستشار المالي صعوبة مؤقتة في الاتصال. يرجى المحاولة بعد قليل."
        return "عذراً يا بطل! 🌐 أواجه صعوبة في الاتصال بالإنترنت الآن. حاول مرة ثانية بعد قليل!"
    elif reason == "safety_guardrail":
        if mode == "parent":
            return "عذراً، يواجه المستشار المالي صعوبة مؤقتة في الاتصال. يرجى المحاولة بعد قليل."
        return "أهلاً بك يا بطل! 🤖 كيف يمكنني مساعدتك اليوم في توفير أموالك وتحقيق أهدافك؟"
    else:
        if mode == "parent":
            return "عذراً، يواجه المستشار المالي صعوبة مؤقتة في الاتصال. يرجى المحاولة بعد قليل."
        return "عذراً يا بطل! 🤖 يواجه صديقك الذكي صعوبة مؤقتة في الاتصال. حاول مرة ثانية بعد قليل!"


class AIProvider(ABC):
    """Abstract base class for AI completion providers."""

    @abstractmethod
    def generate_completion(
        self,
        messages: List[Dict[str, str]],
        mode: str,
        child_name: str = "the child",
    ) -> Dict[str, Any]:
        """
        Generate completion for given conversation messages.

        Returns:
            dict: {"reply": str, "status": str, "provider": str}
            where status is one of ("success", "fallback", "timeout", "rate_limited", "error", "provider_not_configured").
        """
        pass


class OpenAIProvider(AIProvider):
    """
    OpenAI provider implementing strict timeouts, semaphore concurrency limits,
    max_retries=0, and structured error handling.
    """

    def __init__(
        self,
        client: Optional[OpenAI] = None,
        timeout: httpx.Timeout = AI_PROVIDER_TIMEOUT,
        semaphore_wait_seconds: float = AI_SEMAPHORE_WAIT_SECONDS,
        concurrency_limit: int = AI_CONCURRENCY_LIMIT,
        model: str = "gpt-4o-mini",
    ):
        self.client = client
        self.timeout = timeout
        self.semaphore_wait_seconds = semaphore_wait_seconds
        self.semaphore = threading.BoundedSemaphore(concurrency_limit)
        self.model = model

    def generate_completion(
        self,
        messages: List[Dict[str, str]],
        mode: str,
        child_name: str = "the child",
    ) -> Dict[str, Any]:
        if not self.client:
            logger.info("OpenAI client is not configured; returning fallback")
            return {
                "reply": get_arabic_fallback("not_configured", mode=mode),
                "status": "provider_not_configured",
                "provider": "openai",
            }

        acquired = self.semaphore.acquire(timeout=self.semaphore_wait_seconds)
        if not acquired:
            logger.warning("AI Coach concurrency capacity saturated")
            return {
                "reply": get_arabic_fallback("concurrency_limit", mode=mode),
                "status": "rate_limited",
                "provider": "openai",
            }

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=250,
                temperature=0.7,
                timeout=self.timeout,
            )
            raw_reply = response.choices[0].message.content or ""

            # Post-generation safety check
            if 'You are "FinBuddy 🤖"' in raw_reply or "system prompt" in raw_reply.lower():
                return {
                    "reply": get_arabic_fallback("safety_guardrail", mode=mode),
                    "status": "fallback",
                    "provider": "openai",
                }

            return {
                "reply": raw_reply,
                "status": "success",
                "provider": "openai",
            }

        except (APITimeoutError, httpx.TimeoutException) as e:
            logger.error(f"OpenAI API timeout error: {type(e).__name__}")
            return {
                "reply": get_arabic_fallback("timeout", mode=mode),
                "status": "timeout",
                "provider": "openai",
            }
        except RateLimitError as e:
            logger.error(f"OpenAI rate limit error: {type(e).__name__}")
            return {
                "reply": get_arabic_fallback("rate_limited", mode=mode),
                "status": "rate_limited",
                "provider": "openai",
            }
        except APIConnectionError as e:
            logger.error(f"OpenAI connection error: {type(e).__name__}")
            return {
                "reply": get_arabic_fallback("connection_error", mode=mode),
                "status": "error",
                "provider": "openai",
            }
        except AuthenticationError as e:
            logger.error(f"OpenAI authentication error: {type(e).__name__}")
            return {
                "reply": get_arabic_fallback("auth_error", mode=mode),
                "status": "provider_not_configured",
                "provider": "openai",
            }
        except OpenAIError as e:
            logger.error(f"OpenAI provider error: {type(e).__name__}")
            return {
                "reply": get_arabic_fallback("general_error", mode=mode),
                "status": "error",
                "provider": "openai",
            }
        except Exception as e:
            logger.error(f"Unexpected AI Coach error: {type(e).__name__}")
            return {
                "reply": get_arabic_fallback("general_error", mode=mode),
                "status": "error",
                "provider": "openai",
            }
        finally:
            self.semaphore.release()


class MockAIProvider(AIProvider):
    """
    Hermetic Mock AI Provider for testing without network or API keys.
    Supports registering canned responses, custom handlers, and recording call history.
    """

    def __init__(
        self,
        default_reply: str = "تمام! 🤖",
        default_status: str = "success",
        provider_name: str = "mock",
        canned_reply: Optional[str] = None,
    ):
        if canned_reply is not None:
            default_reply = canned_reply
        self.default_reply = default_reply
        self.default_status = default_status
        self.provider_name = provider_name
        self.canned_responses: List[Dict[str, Any]] = []
        self.handler: Optional[Callable[..., Any]] = None
        self.calls: List[Dict[str, Any]] = []

    def register_response(
        self,
        reply: str,
        status: str = "success",
        trigger: Optional[str] = None,
        mode: Optional[str] = None,
    ) -> None:
        """Register a canned response matching an optional text trigger or mode."""
        self.canned_responses.append({
            "reply": reply,
            "status": status,
            "trigger": trigger,
            "mode": mode,
        })

    def set_handler(self, handler: Callable[..., Any]) -> None:
        """Set a dynamic completion handler function: handler(messages, mode, child_name)."""
        self.handler = handler

    def clear(self) -> None:
        """Clear recorded calls and canned responses."""
        self.calls.clear()
        self.canned_responses.clear()
        self.handler = None

    def generate_completion(
        self,
        messages: List[Dict[str, str]],
        mode: str,
        child_name: str = "the child",
    ) -> Dict[str, Any]:
        call_record = {
            "messages": messages,
            "mode": mode,
            "child_name": child_name,
        }
        self.calls.append(call_record)

        if self.handler:
            result = self.handler(messages=messages, mode=mode, child_name=child_name)
            if isinstance(result, dict):
                return {
                    "reply": result.get("reply", self.default_reply),
                    "status": result.get("status", self.default_status),
                    "provider": self.provider_name,
                }
            return {
                "reply": str(result),
                "status": self.default_status,
                "provider": self.provider_name,
            }

        # Check canned responses
        for canned in self.canned_responses:
            if canned.get("mode") and canned["mode"] != mode:
                continue
            trigger = canned.get("trigger")
            if trigger:
                # Search trigger in messages
                found = False
                for m in messages:
                    if trigger.lower() in m.get("content", "").lower():
                        found = True
                        break
                if found:
                    return {
                        "reply": canned["reply"],
                        "status": canned.get("status", "success"),
                        "provider": self.provider_name,
                    }
            else:
                return {
                    "reply": canned["reply"],
                    "status": canned.get("status", "success"),
                    "provider": self.provider_name,
                }

        return {
            "reply": self.default_reply,
            "status": self.default_status,
            "provider": self.provider_name,
        }
