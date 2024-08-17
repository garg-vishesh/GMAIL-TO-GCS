import base64
import os
import requests
import logging
import json
from google.cloud import storage
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from datetime import datetime
from io import BytesIO
import email
from fpdf import FPDF
import PyPDF2
import mimetypes

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Google Cloud Storage client setup
storage_client = storage.Client()

# Credentials setup (replace with your actual credentials)
credentials = {
    'access_token': '#to be filled',
    'refresh_token': '#to be filled',
    'token_uri': 'https://oauth2.googleapis.com/token',
    'client_id': '#to be filled',
    'client_secret': '#to be filled',
}


# Function to convert text to PDF
def convert_text_to_pdf(text):
    pdf = FPDF()
    pdf.add_page()
    pdf.add_font('DejaVu', '', 'DejaVuSansCondensed.ttf', uni=True)
    pdf.set_font('DejaVu', '', 14)

    # Add text to PDF
    pdf.cell(0, 10, txt='Email content:', ln=True)
    pdf.ln(10)
    pdf.multi_cell(0, 10, txt=text)

    # Output PDF to bytes
    pdf_bytes = BytesIO()
    pdf.output(pdf_bytes)
    pdf_bytes.seek(0)

    return pdf_bytes.getvalue()


def convert_attachment_to_pdf(attachment):
    pdf = FPDF()
    pdf.add_page()
    pdf.add_font('DejaVu', '', 'DejaVuSansCondensed.ttf', uni=True)
    pdf.set_font('DejaVu', '', 14)

    # Add text to PDF
    pdf.cell(0, 10, txt='Attachment contents:', ln=True)
    pdf.ln(10)
    pdf.multi_cell(0, 10, txt=attachment.decode('utf-8'))

    # Output PDF to bytes
    pdf_bytes = BytesIO()
    pdf.output(pdf_bytes)
    pdf_bytes.seek(0)

    return pdf_bytes.getvalue()


def refresh_access_token(credentials):
    response = requests.post(credentials['token_uri'], data={
        'grant_type': 'refresh_token',
        'refresh_token': credentials['refresh_token'],
        'client_id': credentials['client_id'],
        'client_secret': credentials['client_secret']
    })
    if response.status_code == 200:
        credentials['access_token'] = response.json()['access_token']
    else:
        raise Exception("Failed to refresh access token")
    return credentials['access_token']


def hello_pubsub(event, context):
    try:
        # Log the entire Pub/Sub message to inspect its structure
        print(f"Received event: {event}")

        # Decode the Pub/Sub message data
        pubsub_message = base64.urlsafe_b64decode(event['data']).decode('utf-8')
        print(f"Decoded Pub/Sub message: {pubsub_message}")

        # Extract the emailAddress and historyId from the Pub/Sub message
        message_json = json.loads(pubsub_message)
        email_address = message_json.get("emailAddress")
        print(f"Extracted email address: {email_address}")

        # Refresh access token if necessary
        access_token = refresh_access_token(credentials)
        gmail_service = build('gmail', 'v1', credentials=Credentials(
            token=access_token,
            refresh_token=credentials['refresh_token'],
            token_uri=credentials['token_uri'],
            client_id=credentials['client_id'],
            client_secret=credentials['client_secret']
        ))
        # Fetch messages from the history to get the latest email ID

        response = gmail_service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
        messages = response.get('messages', [])

        print(f"Extracted messages: {messages}")
        latest_message_id = messages[0]['id']

        print(f"Extracted latest_message_id: {latest_message_id}")

        # Fetch the email content
        # Fetch the email content
        response = gmail_service.users().messages().get(userId='me', id=latest_message_id, format='raw').execute()
        email_content = base64.urlsafe_b64decode(response['raw'])

        # Parse the email content using email library
        msg = email.message_from_bytes(email_content)

        # Extract the email subject and body
        subject = msg['Subject']
        body = ''
        attachments = []
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get('Content-Disposition'))

                # Handle text/plain body
                if ctype == 'text/plain' and 'attachment' not in cdispo:
                    body = part.get_payload(decode=True)  # decode
                # Handle attachments
                elif 'attachment' in cdispo:
                    attachment = part.get_payload(decode=True)
                    attachment_filename = part.get_filename()
                    attachments.append((attachment_filename, attachment))
        else:
            body = msg.get_payload(decode=True)

        # Sanitize the text
        sanitized_sender = sanitize_text(msg['From'])
        sanitized_subject = sanitize_text(subject)
        sanitized_body = sanitize_text(body.decode('utf-8'))

        # Create a PDF from the email data
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt=f"From: {sanitized_sender}", ln=True, align='L')
        pdf.cell(200, 10, txt=f"Subject: {sanitized_subject}", ln=True, align='L')
        pdf.multi_cell(0, 10, txt=f"\n{sanitized_body}")
        pdf_output = f"/tmp/{latest_message_id}.pdf"
        pdf.output(pdf_output)

        # Handle attachments
        for attachment_filename, attachment_data in attachments:
            # Save the attachment to a temporary file
            attachment_temp_file = f"/tmp/{attachment_filename}"
            with open(attachment_temp_file, 'wb') as f:
                f.write(attachment_data)

            # Upload the attachment to GCS
            bucket_name = 'sensitive-data-test-sydney'
            object_name = f"emails/{latest_message_id}/{attachment_filename}"
            bucket = storage_client.bucket(bucket_name)
            blob = bucket.blob(object_name)
            try:
                blob.upload_from_string(open(attachment_temp_file, 'rb').read(),
                                        content_type=mimetypes.guess_type(attachment_filename)[0])
            except Exception as e:
                logger.error(f"Error uploading attachment to GCS: {e}")
                logger.error("Error details:", exc_info=True)

        # Upload the email PDF to GCS
        bucket_name = 'sensitive-data-test-sydney'
        object_name = f"emails/{latest_message_id}.pdf"
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(object_name)
        try:
            blob.upload_from_string(open(pdf_output, 'rb').read(), content_type='application/pdf')
        except Exception as e:
            logger.error(f"Error uploading email to GCS: {e}")
            logger.error("Error details:", exc_info=True)

    except Exception as e:
        logger.error(f"Error processing Pub/Sub message: {e}")
        logger.error("Error details:", exc_info=True)


def sanitize_text(text):
    return text.encode('ascii', 'ignore').decode('ascii')