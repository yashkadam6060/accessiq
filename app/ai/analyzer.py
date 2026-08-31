import os

from dotenv import load_dotenv
from google import genai

load_dotenv()


def analyze_activity(logs):
    """
    Analyze AccessIQ audit logs using local security rules
    and Gemini AI for explanation and recommendation.
    """

    # --------------------------------
    # Local security analysis
    # --------------------------------

    actions = [log.action for log in logs]

    failed_logins = actions.count("FAILED_LOGIN")
    access_denied = actions.count("ACCESS_DENIED")
    successful_logins = actions.count("LOGIN")

    risk_score = 0
    reasons = []

    if failed_logins >= 5:

        risk_score += 40

        reasons.append(
            "Multiple failed login attempts detected."
        )

    elif failed_logins >= 3:

        risk_score += 25

        reasons.append(
            "Several failed login attempts detected."
        )


    if access_denied >= 3:

        risk_score += 40

        reasons.append(
            "Repeated unauthorized access attempts detected."
        )

    elif access_denied >= 1:

        risk_score += 15

        reasons.append(
            "Unauthorized access attempt detected."
        )


    # --------------------------------
    # Risk level
    # --------------------------------

    if risk_score >= 60:

        risk_level = "HIGH"

    elif risk_score >= 30:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    # --------------------------------
    # Risk description
    # --------------------------------

    if risk_level == "HIGH":

        risk_description = (
            "Significant suspicious activity detected. "
            "Immediate administrator review is recommended."
        )

    elif risk_level == "MEDIUM":

        risk_description = (
            "Some unusual security activity was detected. "
            "Administrator review is recommended."
        )

    else:

        risk_description = (
            "Normal security activity detected. "
            "No significant suspicious behavior was identified."
        )


    # --------------------------------
    # Recommended actions
    # --------------------------------

    recommended_actions = []


    if risk_level == "HIGH":

        recommended_actions.append(
            "Review recent failed login attempts immediately."
        )

        recommended_actions.append(
            "Investigate repeated unauthorized access attempts."
        )

        recommended_actions.append(
            "Review the affected user accounts and their permissions."
        )


    elif risk_level == "MEDIUM":

        recommended_actions.append(
            "Review recent failed login attempts."
        )

        recommended_actions.append(
            "Check users involved in unauthorized access attempts."
        )

        recommended_actions.append(
            "Monitor further security activity for unusual behavior."
        )


    else:

        recommended_actions.append(
            "Continue monitoring system activity."
        )

        recommended_actions.append(
            "Review audit logs periodically for unusual behavior."
        )


    # --------------------------------
    # Security reasons
    # --------------------------------

    if not reasons:

        reasons.append(
            "No suspicious activity detected."
        )


    # --------------------------------
    # Prepare recent activity for AI
    # --------------------------------

    recent_logs = logs[:20]

    activity_text = "\n".join(
        f"- {log.action}: {log.details or 'No details'}"
        for log in recent_logs
    )


    # --------------------------------
    # Gemini AI analysis
    # --------------------------------

    ai_explanation = ""
    ai_recommendation = ""


    try:

        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:

            raise ValueError(
                "GEMINI_API_KEY is not configured."
            )


        client = genai.Client(
            api_key=api_key,
            http_options={
                "api_version": "v1"
            }
        )


        prompt = f"""
You are the cybersecurity AI assistant for AccessIQ,
a Role-Based Access Control and security monitoring system.

Analyze the following audit activity.

Security statistics:

Successful logins: {successful_logins}
Failed logins: {failed_logins}
Unauthorized access attempts: {access_denied}

Local calculated risk score: {risk_score}
Local calculated risk level: {risk_level}

Risk description:
{risk_description}

Detected security reasons:
{chr(10).join(reasons)}

Recommended actions:
{chr(10).join(recommended_actions)}

Recent audit activity:
{activity_text}

Provide a concise security assessment.

Return EXACTLY in this format:

EXPLANATION:
<2-3 sentences explaining what the activity means>

RECOMMENDATION:
<1-2 sentences explaining what the administrator should do>

Important:
- Only use information provided above.
- Do not invent events.
- Do not claim that an attack definitely occurred.
- Treat unusual activity as potentially suspicious activity.
"""


        response = client.interactions.create(
            model="gemini-3.5-flash",
            input=prompt
        )


        ai_text = response.output_text.strip()


        # --------------------------------
        # Separate explanation/recommendation
        # --------------------------------

        if "RECOMMENDATION:" in ai_text:

            explanation_part, recommendation_part = (
                ai_text.split(
                    "RECOMMENDATION:",
                    1
                )
            )


            ai_explanation = (
                explanation_part
                .replace("EXPLANATION:", "")
                .strip()
            )


            ai_recommendation = (
                recommendation_part.strip()
            )


        else:

            ai_explanation = ai_text

            ai_recommendation = (
                "Review the recent security activity."
            )


    except Exception as e:

        print("Gemini API error:", e)


        ai_explanation = (
            "AI analysis could not be completed. "
            "The local security analysis is still available."
        )


        ai_recommendation = (
            "Review the audit logs manually."
        )


    # --------------------------------
    # Final result
    # --------------------------------

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