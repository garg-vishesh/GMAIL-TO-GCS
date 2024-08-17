from googleapiclient.discovery import build
from google.oauth2 import credentials
from googleapiclient import errors
import logging
import requests
import time
from google.cloud import secretmanager

# Configure logging
logging.basicConfig(level=logging.INFO)

# Replace with your actual client ID
CLIENT_ID = '##Replace with your values'

# Function to refresh the access token with error handling
def refresh_access_token(refresh_token, client_secret):
    """
    Refreshes the access token using the refresh token, client ID, and client secret.
    Handles potential errors and retries if necessary.
    Returns the new access token or raises an exception on unrecoverable error.
    """

    token_url = 'https://oauth2.googleapis.com/token'
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': CLIENT_ID,
        'client_secret': client_secret
    }

    max_retries = 3  # You can adjust the number of retries
    retry_delay = 2  # Initial retry delay in seconds

    for attempt in range(max_retries):
        try:
            response = requests.post(token_url, data=data)
            response.raise_for_status()  # Raise an exception for error responses

            token_data = response.json()
            return token_data['access_token']

        except requests.exceptions.RequestException as e:
            logging.error(f"Error refreshing access token (attempt {attempt + 1}): {e}")

            if attempt < max_retries - 1:  # Retry if not the last attempt
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
            else:
                raise  # Re-raise the exception after retries are exhausted

def setup_gmail_watch(event, context):
    """Cloud Function (2nd Gen) to set up Gmail push notifications."""

    try:
        logging.info("Starting Gmail watch request setup...")

        # Access Secret Manager to get client_secret
        secret_client = secretmanager.SecretManagerServiceClient()
        project_id = '#replace with your values'
        secret_name = '#replace with your values'
        secret_version = 'latest'
        name = f"projects/{project_id}/secrets/{secret_name}/versions/{secret_version}"
        response = secret_client.access_secret_version(request={"name": name})
        client_secret = response.payload.data.decode('UTF-8')

        # Retrieve the refresh token from your storage (implement this)
        refresh_token = get_refresh_token_from_storage()

        # Refresh the access token with error handling
        access_token = refresh_access_token(refresh_token, client_secret)

        # Create credentials object from the access token
        creds = credentials.Credentials(access_token)

        # Build Gmail service
        gmail_service = build('gmail', 'v1', credentials=creds)

        # Stop the previous watch if it exists
        try:
            gmail_service.users().stop(userId='me').execute()
            logging.info("Stopped previous watch request.")
        except errors.HttpError as e:
            if e.resp.status == 400 and "Precondition check failed" in str(e):
                logging.info("No previous watch request to stop.")
            else:
                logging.error(f"Unexpected error stopping watch request: {e}")
                raise

        # Create a watch request
        request_body = {
            'labelIds': ['INBOX'],
            'topicName': 'projects/gcp-gmail/topics/gmail-new-email-notifications'
        }
        response = gmail_service.users().watch(userId='emails.to.gcs@gmail.com', body=request_body).execute()

        logging.info("Push notifications setup complete: %s", response)

    except Exception as e:
        logging.error('Error setting up push notifications: %s', e)
        # Consider re-raising for retries or implementing more specific error handling
        # raise e