import streamlit as st
import pandas as pd
import base64
import time
import re
import json
from email.mime.text import MIMEText
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

# ========================================
# Streamlit Page Setup
# ========================================
st.set_page_config(page_title="Gmail Mail Merge", layout="wide")
st.title("📧 Gmail Mail Merge Tool")

# ========================================
# Helper Functions
# ========================================
def extract_email(address):
    """Extract clean email address from string"""
    match = re.search(r'[\w\.-]+@[\w\.-]+', str(address))
    return match.group(0) if match else None

def create_message(sender, to, subject, body):
    """Create MIME message for Gmail"""
    message = MIMEText(body, "html")
    message["to"] = to
    message["from"] = sender
    message["subject"] = subject
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {"raw": raw_message}

def get_or_create_label(service, label_name):
    """Find or create a Gmail label"""
    labels = service.users().labels().list(userId="me").execute().get("labels", [])
    for label in labels:
        if label["name"].lower() == label_name.lower():
            return label["id"]

    # Create if not found
    label = (
        service.users()
        .labels()
        .create(
            userId="me",
            body={"name": label_name, "labelListVisibility": "labelShow", "messageListVisibility": "show"}
        )
        .execute()
    )
    return label["id"]

# ========================================
# Step 1: Upload CSV
# ========================================
st.header("📤 Upload Recipients CSV")
uploaded_file = st.file_uploader("Upload your CSV file", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    st.success(f"✅ File uploaded successfully with {len(df)} rows.")
    st.dataframe(df.head())

    # ========================================
    # Step 2: Compose Email
    # ========================================
    st.header("📝 Compose Email")
    subject_template = st.text_input("Subject", "Hello {{Name}}")
    body_template = st.text_area(
        "Body (HTML supported)",
        "Dear {{Name}},<br><br>This is a test mail merge message.<br><br>Best regards,<br>Your Company"
    )

    # ========================================
    # Step 3: Gmail Auth
    # ========================================
    st.header("🔐 Connect Your Gmail Account")

    client_secret_file = st.file_uploader("Upload your Gmail API credentials (client_secret.json)", type=["json"])
    token_file = "token.json"

    creds = None
    if client_secret_file:
        creds_data = json.load(client_secret_file)
        st.info("📂 Credentials file loaded.")

        flow = Flow.from_client_config(
            creds_data,
            scopes=["https://www.googleapis.com/auth/gmail.modify", "https://www.googleapis.com/auth/gmail.compose"],
            redirect_uri="urn:ietf:wg:oauth:2.0:oob"
        )

        auth_url, _ = flow.authorization_url(prompt="consent")
        st.markdown(f"[Click here to authorize Gmail access]({auth_url})")

        auth_code = st.text_input("Enter the authorization code from Gmail:")

        if auth_code:
            flow.fetch_token(code=auth_code)
            creds = flow.credentials
            with open(token_file, "w") as token:
                token.write(creds.to_json())
            st.success("✅ Gmail authorized successfully!")

    # ========================================
    # Step 4: Label and Timing
    # ========================================
    st.header("🏷️ Label & Timing Options")
    label_name = st.text_input("Gmail label to apply (new emails only)", "Mail Merge Sent")
    delay_seconds = st.number_input("Delay between emails (seconds)", min_value=0, value=60, step=5)

    # Add new send mode
    send_mode = st.radio(
        "Choose sending mode",
        ["🆕 New Email", "↩️ Follow-up (Reply)", "💾 Save as Draft"]
    )

    # ========================================
    # Step 5: Send / Draft Emails
    # ========================================
    if creds and st.button("🚀 Send Emails"):
        service = build("gmail", "v1", credentials=creds)
        sent_count, skipped, errors = 0, [], []

        with st.spinner("📨 Processing emails... please wait."):
            label_id = get_or_create_label(service, label_name)

            for idx, row in df.iterrows():
                try:
                    to_addr = extract_email(row.get("Email", ""))
                    if not to_addr:
                        skipped.append(idx)
                        continue

                    # Render subject and body templates
                    subject = subject_template
                    body = body_template
                    for col in df.columns:
                        subject = subject.replace(f"{{{{{col}}}}}", str(row[col]))
                        body = body.replace(f"{{{{{col}}}}}", str(row[col]))

                    msg_body = create_message("me", to_addr, subject, body)

                    # 🆕 New Email or ↩️ Follow-up or 💾 Save as Draft
                    if send_mode == "💾 Save as Draft":
                        draft = service.users().drafts().create(userId="me", body={"message": msg_body}).execute()
                        st.info(f"📝 Draft saved for {to_addr}")
                        sent_count += 1
                    elif send_mode == "↩️ Follow-up (Reply)":
                        thread_id = row.get("ThreadId", "")
                        if not thread_id:
                            skipped.append(idx)
                            continue
                        msg_body["threadId"] = thread_id
                        sent_msg = service.users().messages().send(userId="me", body=msg_body).execute()
                        st.success(f"↩️ Follow-up sent to {to_addr}")
                        sent_count += 1
                    else:
                        sent_msg = service.users().messages().send(userId="me", body=msg_body).execute()
                        service.users().messages().modify(
                            userId="me", id=sent_msg["id"], body={"addLabelIds": [label_id]}
                        ).execute()
                        st.success(f"✅ Mail sent to {to_addr}")
                        sent_count += 1

                    time.sleep(delay_seconds)

                except Exception as e:
                    errors.append((idx, str(e)))
                    continue

        st.success(f"🎉 Completed — {sent_count} processed successfully.")
        if skipped:
            st.warning(f"⏭️ Skipped {len(skipped)} entries (missing email or thread).")
        if errors:
            st.error(f"⚠️ {len(errors)} errors encountered. See console logs for details.")
