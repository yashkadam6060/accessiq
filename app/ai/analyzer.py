
import os
import time
import hashlib

from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

# Cache successful Gemini responses for 5 minutes.
GEMINI_CACHE = {}
GEMINI_CACHE_TTL = 300

# Pause new Gemini requests for 1 hour after a quota error.
GEMINI_COOLDOWN_UNTIL = 0


def analyze_activity(
    logs,
    successful_logins=None,
    failed_logins=None,
    access_denied=None,
    use_ai=True
):
    """Analyze AccessIQ audit logs with local analysis and optional Gemini."""

    global GEMINI_COOLDOWN_UNTIL

    # --------------------------------
    # Local security analysis
    # --------------------------------

    if (
        successful_logins is None
        or failed_logins is None
        or access_denied is None
    ):
        actions = [log.action for log in logs]

        failed_logins = actions.count("FAILED_LOGIN")
        access_denied = actions.count("ACCESS_DENIED")
        successful_logins = actions.count("LOGIN")

    risk_score = 0
    reasons = []

    if failed_logins >= 5:
        risk_score += 40
        reasons.append("Multiple failed login attempts detected.")
    elif failed_logins >= 3:
        risk_score += 25
        reasons.append("Several failed login attempts detected.")

    if access_denied >= 3:
        risk_score += 40
        reasons.append("Repeated unauthorized access attempts detected.")
    elif access_denied >= 1:
        risk_score += 15
        reasons.append("Unauthorized access attempt detected.")

    if risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if risk_level == "HIGH":
        risk_description = (
            "Significant suspicious activity detected. "
            "Immediate administrator review is recommended."
        )
        recommended_actions = [
            "Review recent failed login attempts immediately.",
            "Investigate repeated unauthorized access attempts.",
            "Review the affected user accounts and their permissions."
        ]
    elif risk_level == "MEDIUM":
        risk_description = (
            "Some unusual security activity was detected. "
            "Administrator review is recommended."
        )
        recommended_actions = [
            "Review recent failed login attempts.",
            "Check users involved in unauthorized access attempts.",
            "Monitor further security activity for unusual behavior."
        ]
    else:
        risk_description = (
            "Normal security activity detected. "
            "No significant suspicious behavior was identified."
        )
        recommended_actions = [
            "Continue monitoring system activity.",
            "Review audit logs periodically for unusual behavior."
        ]

    if not reasons:
        reasons.append("No suspicious activity detected.")

    # --------------------------------
    # Local fallback messages
    # --------------------------------

    ai_explanation = (
        "The security dashboard is using local security analysis "
        "based on the recorded audit activity."
    )

    ai_recommendation = (
        "Continue monitoring audit logs and review any unusual "
        "failed login or unauthorized access activity."
    )

    if not use_ai:
        return {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "risk_description": risk_description,
            "recommended_actions": recommended_actions,
            "successful_logins": successful_logins,
            "failed_logins": failed_logins,
            "access_denied": access_denied,
            "reasons": reasons,
            "recommendation": ai_recommendation,
            "ai_explanation": ai_explanation
        }

    # --------------------------------
    # Prepare a small Gemini request
    # --------------------------------

    recent_logs = logs[:20]

    activity_text = "\n".join(
        f"- {log.action}: {log.details or 'No details'}"
        for log in recent_logs
    )

    prompt = f"""
You are the cybersecurity AI assistant for AccessIQ,
a Role-Based Access Control and security monitoring system.

Analyze the following audit activity.

Successful logins: {successful_logins}
Failed logins: {failed_logins}
Unauthorized access attempts: {access_denied}

Local risk score: {risk_score}
Local risk level: {risk_level}

Risk description:
{risk_description}

Detected security reasons:
{chr(10).join(reasons)}

Recommended actions:
{chr(10).join(recommended_actions)}

Recent audit activity:
{activity_text}

Provide a concise security assessment using exactly this format:

EXPLANATION:
Write 2-3 sentences explaining what the activity means.

RECOMMENDATION:
Write 1-2 sentences explaining what the administrator should do.

Use only the supplied information. Do not invent events or claim
that an attack definitely occurred.
"""

    # --------------------------------
    # Cache and quota cooldown
    # --------------------------------

    cache_key = hashlib.sha256(
        prompt.encode("utf-8")
    ).hexdigest()

    now = time.monotonic()
    cached = GEMINI_CACHE.get(cache_key)

    if cached and now < cached["expires"]:
        ai_explanation = cached["explanation"]
        ai_recommendation = cached["recommendation"]

    elif now < GEMINI_COOLDOWN_UNTIL:
        ai_explanation = (
            "Gemini analysis is temporarily paused because the API "
            "quota was exceeded. Local security analysis is available."
        )
        ai_recommendation = (
            "Review the local security recommendations and try Gemini "
            "again after the cooldown period."
        )

    else:
        try:
            api_key = os.getenv("GEMINI_API_KEY")

            if not api_key:
                raise ValueError(
                    "GEMINI_API_KEY is not configured."
                )

            client = genai.Client(
                api_key=api_key,
                http_options=types.HttpOptions(
                    api_version="v1beta",
                    timeout=15000,
                    retry_options=types.HttpRetryOptions(
                        attempts=1
                    )
                )
            )

            response = client.interactions.create(
                model="gemini-3.5-flash",
                input=prompt
            )

            ai_text = (response.output_text or "").strip()

            if not ai_text:
                raise ValueError(
                    "Gemini returned an empty response."
                )

            if "RECOMMENDATION:" in ai_text:
                explanation_part, recommendation_part = (
                    ai_text.split("RECOMMENDATION:", 1)
                )

                ai_explanation = (
                    explanation_part
                    .replace("EXPLANATION:", "")
                    .strip()
                )

                ai_recommendation = recommendation_part.strip()
            else:
                ai_explanation = ai_text
                ai_recommendation = (
                    "Review the recent security activity."
                )

            GEMINI_CACHE[cache_key] = {
                "explanation": ai_explanation,
                "recommendation": ai_recommendation,
                "expires": time.monotonic() + GEMINI_CACHE_TTL
            }

        except Exception as e:
            error_text = str(e).lower()
            print("Gemini API error:", e)

            if (
                "429" in error_text
                or "too_many_requests" in error_text
                or "resource_exhausted" in error_text
                or "quota" in error_text
            ):
                GEMINI_COOLDOWN_UNTIL = (
                    time.monotonic() + 3600
                )

            ai_explanation = (
                "AI analysis is temporarily unavailable. "
                "The local security analysis is still available."
            )

            ai_recommendation = (
                "Review the audit logs and the local security "
                "recommendations shown above."
            )

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_description": risk_description,
        "recommended_actions": recommended_actions,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "access_denied": access_denied,
        "reasons": reasons,
        "recommendation": ai_recommendation,
        "ai_explanation": ai_explanation
    }
