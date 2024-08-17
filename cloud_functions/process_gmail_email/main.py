import base64
import os
import requests
import logging
import json
from google.cloud import storage
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from fpdf import FPDF
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO)

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


# def create_pdf(email_data, email_id):
#     pdf = FPDF()
#     pdf.add_page()
#     pdf.set_font("Arial", size=12)

#     # Add sender
#     pdf.cell(200, 10, txt=f"From: {email_data['sender']}", ln=True, align='L')

#     # Add subject
#     pdf.cell(200, 10, txt=f"Subject: {email_data['subject']}", ln=True, align='L')

#     # Add email body
#     pdf.multi_cell(0, 10, txt=f"\n{email_data['body']}")

#     # Save the PDF
#     pdf_output = f"/tmp/{email_id}.pdf"
#     pdf.output(pdf_output)

#     return pdf_output

def upload_to_gcs(bucket_name, blob_name, file_path):
    bucket = storage_client.get_bucket(bucket_name)
    blob = bucket.blob(blob_name)
    blob.upload_from_filename(file_path)
    print(f"Successfully uploaded {blob_name} to {bucket_name}")


# def process_email(gmail_service, message):
#     email_id = message['id']
#     email_data = {
#         'sender': '',
#         'subject': '',
#         'body': '',
#     }

#     # Get the sender and subject
#     headers = message['payload'].get('headers', [])
#     for header in headers:
#         if header['name'] == 'From':
#             email_data['sender'] = header['value']
#         if header['name'] == 'Subject':
#             email_data['subject'] = header['value']

#     # Get the email body
#     if 'parts' in message['payload']:
#         parts = message['payload']['parts']
#         for part in parts:
#             if part['mimeType'] == 'text/plain':
#                 email_data['body'] = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
#                 break  # Only take the first text/plain part
#     else:
#         email_data['body'] = base64.urlsafe_b64decode(message['payload']['body']['data']).decode('utf-8')

#     # Create a PDF from the email content
#     pdf_file_path = create_pdf(email_data, email_id)

#     # Upload the PDF to GCS
#     bucket_name = 'sensitive-data-test-sydney'  # Replace with your bucket name
#     upload_to_gcs(bucket_name, f'emails/{email_id}.pdf', pdf_file_path)

#     print(f"Successfully processed and uploaded email {email_id}")

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
        history_id = message_json.get("historyId")

        print(f"Extracted email address: {email_address}")
        print(f"Extracted history ID: {history_id}")

        if not history_id:
            raise Exception("No history ID found in the message.")

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
        response = gmail_service.users().messages().get(userId='me', id=latest_message_id, format='raw').execute()
        email_content = base64.urlsafe_b64decode(response['raw'])

        # Convert the email content to an .eml file
        eml_file = f"{latest_message_id}.eml"
        with open(eml_file, 'wb') as f:
            f.write(email_content)

        bucket_name = 'sensitive-data-test-sydney'
        now = datetime.now()
        object_name = f"emails/{latest_message_id}.eml"

        logging.info(f"Storing email in GCS at: {object_name}")

        # Store the .eml file in GCS
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(object_name)
        blob.upload_from_filename(eml_file, content_type='message/rfc822')
        logging.info(f'Email processed and stored in GCS.')

    except Exception as e:
        logging.error(f'An error occurred: {e}')