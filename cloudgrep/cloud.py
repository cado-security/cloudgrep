import boto3
from azure.storage.blob import BlobServiceClient, BlobProperties
from azure.identity import DefaultAzureCredential
from azure.core.exceptions import ResourceNotFoundError
from google.cloud import storage  # type: ignore
from datetime import datetime
import botocore
import concurrent
import tempfile
from typing import Iterator, Optional, List, Any
import logging
from cloudgrep.search import Search


class Cloud:
    def download_from_s3_multithread(
        self,
        bucket: str,
        files: List[str],
        query: List[str],
        hide_filenames: bool,
        yara_rules: Any,
        log_type: Optional[str] = None,
        log_format: Optional[str] = None,
        log_properties: List[str] = [],
        json_output: Optional[bool] = False,
    ) -> int:
        """Use ThreadPoolExecutor and boto3 to download every file in the bucket from s3
        Returns number of matched files"""
        client_config = botocore.config.Config(
            max_pool_connections=64,
        )
        matched_count = 0
        s3 = boto3.client("s3", config=client_config)
        # Create a function to download the files
        def download_file(key: str) -> None:
            # Get meta data of file in s3 using boto3
            with tempfile.NamedTemporaryFile() as tmp:
                tmp.close() # fixes issue on windows
                logging.info(f"Downloading {bucket} {key} to {tmp.name}")
                s3.download_file(bucket, key, tmp.name)
                matched = Search().search_file(
                    tmp.name, key, query, hide_filenames, yara_rules, log_type, log_format, log_properties, json_output
                )
                if matched:
                    nonlocal matched_count
                    matched_count += 1

        # Use ThreadPoolExecutor to download the files
        with concurrent.futures.ThreadPoolExecutor() as executor:  # type: ignore
            executor.map(download_file, files)
        # For debugging, run in a single thread for clearer logging:
        # for file in files:
        #    download_file(file)

        return matched_count

    def download_from_azure(
        self,
        account_name: str,
        container_name: str,
        files: List[str],
        query: List[str],
        hide_filenames: bool,
        yara_rules: Any,
        log_type: Optional[str] = None,
        log_format: Optional[str] = None,
        log_properties: List[str] = [],
        json_output: Optional[bool] = False,
    ) -> int:
        """Download every file in the container from azure
        Returns number of matched files"""
        default_credential = DefaultAzureCredential()
        matched_count = 0
        blob_service_client = BlobServiceClient.from_connection_string(
            f"DefaultEndpointsProtocol=https;AccountName={account_name};EndpointSuffix=core.windows.net",
            credential=default_credential,
        )
        container_client = blob_service_client.get_container_client(container_name)

        def download_file(key: str) -> None:
            with tempfile.NamedTemporaryFile() as tmp:
                tmp.close() # fixes issue on windows
                logging.info(f"Downloading {account_name}/{container_name} {key} to {tmp.name}")
                try:
                    blob_client = container_client.get_blob_client(key)
                    with open(tmp.name, "wb") as my_blob:
                        blob_data = blob_client.download_blob()
                        blob_data.readinto(my_blob)
                    matched = Search().search_file(
                        tmp.name,
                        key,
                        query,
                        hide_filenames,
                        yara_rules,
                        log_type,
                        log_format,
                        log_properties,
                        json_output,
                        account_name,
                    )
                    if matched:
                        nonlocal matched_count
                        matched_count += 1
                except ResourceNotFoundError:
                    logging.info(f"File {key} not found in {account_name}/{container_name}")

        # Use ThreadPoolExecutor to download the files
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.map(download_file, files)

        return matched_count

    def download_from_google(
        self,
        bucket: str,
        files: List[str],
        query: List[str],
        hide_filenames: bool,
        yara_rules: Any,
        log_type: Optional[str] = None,
        log_format: Optional[str] = None,
        log_properties: List[str] = [],
        json_output: Optional[bool] = False,
    ) -> int:
        """Download every file in the bucket from google
        Returns number of matched files"""

        matched_count = 0
        client = storage.Client()
        bucket_gcp = client.get_bucket(bucket)

        def download_file(key: str) -> None:
            with tempfile.NamedTemporaryFile() as tmp:
                tmp.close() # fixes issue on windows
                logging.info(f"Downloading {bucket} {key} to {tmp.name}")
                blob = bucket_gcp.get_blob(key)
                blob.download_to_filename(tmp.name)
                matched = Search().search_file(
                    tmp.name, key, query, hide_filenames, yara_rules, log_type, log_format, log_properties, json_output
                )
                if matched:
                    nonlocal matched_count
                    matched_count += 1

        # Use ThreadPoolExecutor to download the files
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.map(download_file, files)

        return matched_count

    def filter_object(
        self,
        obj: dict,
        key_contains: Optional[str],
        from_date: Optional[datetime],
        to_date: Optional[datetime],
        file_size: int,
    ) -> bool:
        last_modified = obj["LastModified"]
        if last_modified and from_date and from_date > last_modified:
            return False  # Object was modified before the from_date
        if last_modified and to_date and last_modified > to_date:
            return False  # Object was modified after the to_date
        if obj["Size"] == 0 or obj["Size"] > file_size:
            return False  # Object is empty or too large
        if key_contains and key_contains not in obj["Key"]:
            return False  # Object does not contain the key_contains string
        return True

    def filter_object_azure(
        self,
        obj: BlobProperties,
        key_contains: Optional[str],
        from_date: Optional[datetime],
        to_date: Optional[datetime],
        file_size: int,
    ) -> bool:
        last_modified = obj["last_modified"]
        if last_modified and from_date and from_date > last_modified:
            return False  # Object was modified before the from_date
        if last_modified and to_date and last_modified > to_date:
            return False  # Object was modified after the to_date
        if obj["size"] == 0 or obj["size"] > file_size:
            return False  # Object is empty or too large
        if key_contains and key_contains not in obj["name"]:
            return False  # Object does not contain the key_contains string
        return True

    def filter_object_google(
        self,
        obj: storage.blob.Blob,
        key_contains: Optional[str],
        from_date: Optional[datetime],
        to_date: Optional[datetime],
    ) -> bool:
        last_modified = obj.updated
        if last_modified and from_date and from_date > last_modified:
            return False
        if last_modified and to_date and last_modified > to_date:
            return False
        if key_contains and key_contains not in obj.name:
            return False
        return True

    def get_objects(
        self,
        bucket: str,
        prefix: Optional[str],
        key_contains: Optional[str],
        from_date: Optional[datetime],
        end_date: Optional[datetime],
        file_size: int,
    ) -> Iterator[str]:
        """Get all objects in a bucket with a given prefix"""
        s3 = boto3.client("s3")
        paginator = s3.get_paginator("list_objects_v2")
        page_iterator = paginator.paginate(Bucket=bucket, Prefix=prefix)
        for page in page_iterator:
            if "Contents" in page:
                for obj in page["Contents"]:
                    if self.filter_object(obj, key_contains, from_date, end_date, file_size):
                        yield obj["Key"]

    def get_azure_objects(
        self,
        account_name: str,
        container_name: str,
        prefix: Optional[str],
        key_contains: Optional[str],
        from_date: Optional[datetime],
        end_date: Optional[datetime],
        file_size: int,
    ) -> Iterator[str]:
        default_credential = DefaultAzureCredential()
        """ Get all objects in Azure storage container with a given prefix """
        blob_service_client = BlobServiceClient.from_connection_string(
            f"DefaultEndpointsProtocol=https;AccountName={account_name};EndpointSuffix=core.windows.net",
            credential=default_credential,
        )
        container_client = blob_service_client.get_container_client(container_name)
        blobs = container_client.list_blobs(name_starts_with=prefix)

        for blob in blobs:

            if self.filter_object_azure(
                blob,
                key_contains,
                from_date,
                end_date,
                file_size,
            ):
                yield blob.name

    def get_google_objects(
        self,
        bucket: str,
        prefix: Optional[str],
        key_contains: Optional[str],
        from_date: Optional[datetime],
        end_date: Optional[datetime],
    ) -> Iterator[str]:
        """Get all objects in a GCP bucket with a given prefix"""
        client = storage.Client()
        bucket_gcp = client.get_bucket(bucket)
        blobs = bucket_gcp.list_blobs(prefix=prefix)
        for blob in blobs:
            if self.filter_object_google(
                blob,
                key_contains,
                from_date,
                end_date,
            ):
                yield blob.name
