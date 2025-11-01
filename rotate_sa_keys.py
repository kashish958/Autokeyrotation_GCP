# rotate_sa_keys.py
import base64
import json
import os
from datetime import datetime, timezone
from googleapiclient import discovery
from google.cloud import secretmanager
from google.auth import default

# --------- CONFIG ----------
PROJECT_ID = "platinum-wave-403112"
SERVICE_ACCOUNTS = [
    "testalways@platinum-wave-403112.iam.gserviceaccount.com"
    # add all 12 service accounts here
]
KEY_MAX_AGE_DAYS = 90            # policy: keys should be rotated every 90 days
ROTATE_BEFORE_DAYS = 2           # rotate when <= 2 days left
ROTATE_THRESHOLD_DAYS = KEY_MAX_AGE_DAYS - ROTATE_BEFORE_DAYS
KEYS_TO_KEEP = 1
SAVE_KEY_PATH = "/workspace"     # Cloud Build writable workspace
# ---------------------------

def get_iam_service():
    creds, _ = default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    return discovery.build("iam", "v1", credentials=creds)

def list_existing_keys(iam_service, sa_email):
    sa_resource = f"projects/{PROJECT_ID}/serviceAccounts/{sa_email}"
    keys = iam_service.projects().serviceAccounts().keys().list(name=sa_resource).execute()
    return [k for k in keys.get("keys", []) if k["keyType"] == "USER_MANAGED"]

def key_age_days(key):
    created = datetime.fromisoformat(key["validAfterTime"].replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - created).days

def needs_rotation(latest_key):
    return key_age_days(latest_key) >= ROTATE_THRESHOLD_DAYS

def create_new_key(iam_service, sa_email):
    sa_resource = f"projects/{PROJECT_ID}/serviceAccounts/{sa_email}"
    resp = iam_service.projects().serviceAccounts().keys().create(name=sa_resource, body={}).execute()
    key_data = base64.b64decode(resp["privateKeyData"])
    filename = os.path.join(SAVE_KEY_PATH, f"{sa_email.replace('@','_').replace('.','_')}_key.json")
    with open(filename, "wb") as f:
        f.write(key_data)
    print(f"Created key and saved to {filename}")
    return filename

def delete_old_keys(iam_service, sa_email, keys):
    sorted_keys = sorted(keys, key=lambda k: k["validAfterTime"], reverse=True)
    for k in sorted_keys[KEYS_TO_KEEP:]:
        iam_service.projects().serviceAccounts().keys().delete(name=k["name"]).execute()
        print(f"Deleted old key: {k['name']}")

def ensure_secret_and_upload(secret_client, secret_id, file_path):
    parent = f"projects/{PROJECT_ID}"
    secret_name = f"{parent}/secrets/{secret_id}"
    try:
        secret_client.get_secret(name=secret_name)
    except Exception:
        secret_client.create_secret(parent=parent, secret_id=secret_id, secret={"replication": {"automatic": {}}})
        print(f"Created secret: {secret_id}")
    with open(file_path, "r") as f:
        payload = f.read()
    secret_client.add_secret_version(parent=secret_name, payload={"data": payload.encode("utf-8")})
    print(f"Uploaded new version to secret: {secret_id}")

def rotate_for_sa(iam_service, sa_email):
    print(f"Checking {sa_email}")
    keys = list_existing_keys(iam_service, sa_email)
    if not keys:
        print("No user-managed keys found — creating one now.")
        new_file = create_new_key(iam_service, sa_email)
        secret_client = secretmanager.SecretManagerServiceClient()
        ensure_secret_and_upload(secret_client, sa_email.split('@')[0].replace('-', '_'), new_file)
        return

    latest = sorted(keys, key=lambda k: k["validAfterTime"], reverse=True)[0]
    age = key_age_days(latest)
    print(f"Latest key age (days): {age}")
    if needs_rotation(latest):
        print("Rotation needed — creating new key.")
        new_file = create_new_key(iam_service, sa_email)
        secret_client = secretmanager.SecretManagerServiceClient()
        ensure_secret_and_upload(secret_client, sa_email.split('@')[0].replace('-', '_'), new_file)
        delete_old_keys(iam_service, sa_email, keys)
    else:
        print("No rotation required.")

def main():
    iam = get_iam_service()
    for sa in SERVICE_ACCOUNTS:
        try:
            rotate_for_sa(iam, sa)
        except Exception as e:
            print(f"Error processing {sa}: {e}")

if __name__ == "__main__":
    main()
