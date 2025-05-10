import argparse
import boto3
from os import getenv
from dotenv import load_dotenv
import logging
from botocore.exceptions import ClientError
from urllib.request import urlopen
import io
import json
import magic




# Configure logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
       #logging.FileHandler("logs/s3_cli.log"),   # File output
        logging.StreamHandler()                  # Console output
    ]
)

ALLOWED_MIME_TYPES = {
    "image/bmp",
    "image/jpeg",
    "image/png",
    "image/webp",
    "video/mp4"
}


def init_client():
    try:
        client = boto3.client(
            "s3",
            aws_access_key_id=getenv("aws_access_key_id"),
            aws_secret_access_key=getenv("aws_secret_access_key"),
            aws_session_token=getenv("aws_session_token"),
            region_name=getenv("aws_region_name")
        )
        return client
    except ClientError as e:
        logging.error(f"AWS Client Error: {e}")
    except Exception as e:
        logging.error(f"Unexpected Error: {e}")

def list_buckets(s3_client):
    try:
        response = s3_client.list_buckets()
        return response.get("Buckets", [])
    except ClientError as e:
        logging.error(f"AWS Client Error: {e}")
        return []
    except Exception as e:
        logging.error(f"Unexpected Error: {e}")
        return []

def create_bucket(s3_client, bucket_name, region='us-west-2'):
    try:
        location = {'LocationConstraint': region}
        s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration=location
        )
        logging.info(f"bucket {bucket_name} created successfully")
        return True
    except ClientError as e:
        logging.error(f"AWS Client Error: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected Error: {e}")
        return False

def delete_bucket(s3_client, bucket_name):
    try:
        s3_client.delete_bucket(Bucket=bucket_name)
        logging.info(f"bucket {bucket_name} deleted successfully")
        return True
    except ClientError as e:
        logging.error(f"AWS Client Error: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected Error: {e}")
        return False

def bucket_exists(s3_client, bucket_name):
    try:
        s3_client.head_bucket(Bucket=bucket_name)
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == '404':
            return False
        else:
            logging.error(f"AWS Client Error: {e}")
            return False
    except Exception as e:
        logging.error(f"Unexpected Error: {e}")
        return False
    
def download_file_and_upload_to_s3(s3_client, bucket_name, url, file_name, keep_local=False):
    try:
        with urlopen(url) as response:
            content = response.read()
            mime = magic.from_buffer(content, mime=True)

            if mime not in ALLOWED_MIME_TYPES:
              logging.error(f"Unsupported file type: {mime}")
              return None

            s3_client.upload_fileobj(
                Fileobj=io.BytesIO(content),
                Bucket=bucket_name,
                Key=file_name
            )

        if keep_local:
            with open(file_name, mode='wb') as jpg_file:
                jpg_file.write(content)

        return "https://s3-{0}.amazonaws.com/{1}/{2}".format(
            'us-west-2', 
            bucket_name,
            file_name
        )
    except Exception as e:  
        logging.error(f"Error uploading file to S3: {e}")

def generate_public_read_policy(bucket_name):
    policy = {
        "Version":
        "2012-10-17",
        "Statement": [{
            "Sid": "PublicReadGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket_name}/*",
        }],
    }

    return json.dumps(policy)

def set_object_access_policy(client, bucket_name, key):
    try:
        client.put_object_acl(ACL='public-read', Bucket=bucket_name, Key=key)
        logging.info(f"Public-read access granted for {key}.")
    except ClientError as e:
        logging.error(f"Failed to set access policy: {e}")

def create_bucket_policy(s3_client, bucket_name):
    policy = generate_public_read_policy(bucket_name)
    try:
        s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
        logging.info("Bucket policy created.")
    except ClientError as e:
        logging.error(f"Failed to create policy: {e}")


def read_bucket_policy(client, bucket_name):
    try:
        result = client.get_bucket_policy(Bucket=bucket_name)
        logging.info(f"Bucket Policy:\n{result['Policy']}")
    except ClientError as e:
        logging.error(f"Failed to read policy: {e}")


    return

if __name__ == "__main__":
    load_dotenv()
    client = init_client()

    parser = argparse.ArgumentParser(description="S3 CLI Tool")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("list", help="List all buckets")

    create = subparsers.add_parser("create", help="Create a new bucket")
    create.add_argument("bucket")

    delete = subparsers.add_parser("delete", help="Delete an existing bucket")
    delete.add_argument("bucket")

    exists = subparsers.add_parser("exists", help="Check if bucket exists")
    exists.add_argument("bucket")

    upload = subparsers.add_parser("upload", help="Upload a file to bucket")
    upload.add_argument("url")
    upload.add_argument("bucket")
    upload.add_argument("key")

    
    args = parser.parse_args()
    if args.command == "list":
        print(list_buckets(client))
    elif args.command == "create":
        create_bucket(client, args.bucket)
    elif args.command == "delete":
        delete_bucket(client, args.bucket)
    elif args.command == "exists":
        print(bucket_exists(client, args.bucket))
    elif args.command == "upload":
        print(download_file_and_upload_to_s3(client, args.bucket, args.url, args.key))

