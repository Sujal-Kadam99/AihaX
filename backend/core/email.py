"""SMTP Email sending service with Mock Logging fallback for developer testing."""

import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger("aihax.email")

def send_smtp_email(to_email: str, subject: str, body: str) -> bool:
    """Send an SMTP email or fallback to logging mock emails when not configured."""
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = os.environ.get("SMTP_PORT", "587")
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    smtp_from = os.environ.get("SMTP_FROM", "no-reply@aihax.com")

    # If SMTP is not fully configured, log a detailed mock email message
    if not smtp_host or not smtp_user or not smtp_pass:
        print("\n[MOCK EMAIL SENT] ======================================")
        print(f"TO: {to_email}")
        print(f"FROM: {smtp_from}")
        print(f"SUBJECT: {subject}")
        print(f"BODY:\n{body}")
        print("========================================================\n")
        logger.info(f"Mock email sent to {to_email} (Subject: {subject})")
        return True

    try:
        msg = MIMEMultipart()
        msg["From"] = smtp_from
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        port = int(smtp_port)
        if port == 465:
            server = smtplib.SMTP_SSL(smtp_host, port, timeout=10)
        else:
            server = smtplib.SMTP(smtp_host, port, timeout=10)
            server.starttls()

        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_from, to_email, msg.as_string())
        server.quit()
        logger.info(f"SMTP email successfully sent to {to_email}")
        return True
    except Exception as exc:
        logger.error(f"Failed to send SMTP email to {to_email}: {exc}")
        # Always print warning/mock fallback so it doesn't crash developer flow
        print("\n[SMTP FAILED - MOCK FALLBACK] ==========================")
        print(f"ERROR: {exc}")
        print(f"TO: {to_email}")
        print(f"SUBJECT: {subject}")
        print(f"BODY:\n{body}")
        print("========================================================\n")
        return False
