import boto3
import os
from azure.storage.blob import BlobServiceClient, BlobProperties
from azure.identity import DefaultAzureCredential
from azure.core.exceptions import ResourceNotFoundError
from google.cloud import storage  # type: ignore
from datetime import datetime
import botocore
import concurrent.futures
import tempfile
from typing import Iterator, Optional, List, Any
import logging
from cloudgrep.search import Search


class Cloud:
    def __init__(self) -> None:
        self.search = Search()

    def _download_and_search_in_parallel(self, files: List[str], worker_func) -> int:
        """ Use ThreadPoolExecutorto download every file
        Returns number of matched files """
        total_matched = 0
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(worker_func, key) for key in files]
            for fut in concurrent.futures.as_completed(futures):
                total_matched += fut.result()
        return total_matched

    def download_from_s3_multithread(
        self,
        bucket: str,
        files: List[str],
        query: List[str],
        hide_filenames: bool,
        yara_rules: Any,
        log_format: Optional[str] = None,
        log_properties: List[str] = [],
        json_output: Optional[bool] = False,
    ) -> int:
        """Use ThreadPoolExecutor and boto3 to download every file in the bucket from s3
        Returns number of matched files"""
        if not log_properties:
            log_properties = []

        s3 = boto3.client("s3", config=botocore.config.Config(max_pool_connections=64))

        def _download_search_s3(key: str) -> int:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp_name = tmp.name
            try:
                logging.info(f"Downloading s3://{bucket}/{key} to {tmp_name}")
                s3.download_file(bucket, key, tmp_name)
                matched = self.search.search_file(
                    tmp_name, key, query, hide_filenames, yara_rules, log_format, log_properties, json_output
                )
                return 1 if matched else 0
            except Exception as e:
                logging.error(f"Error downloading or searching {key}: {e}")
                return 0
            finally:
                try:
                    os.remove(tmp_name)
                except OSError:
                    pass

        return self._download_and_search_in_parallel(files, _download_search_s3)

    def download_from_azure(
        self,
        account_name: str,
        container_name: str,
        files: List[str],
        query: List[str],
        hide_filenames: bool,
        yara_rules: Any,
        log_format: Optional[str] = None,
        log_properties: Optional[List[str]] = None,
        json_output: bool = False,
    ) -> int:
        """Download every file in the container from azure
        Returns number of matched files"""
        if not log_properties:
            log_properties = []

        default_credential = DefaultAzureCredential()
        blob_service_client = BlobServiceClient.from_connection_string(
            f"DefaultEndpointsProtocol=https;AccountName={account_name};EndpointSuffix=core.windows.net",
            credential=default_credential,
        )
        container_client = blob_service_client.get_container_client(container_name)

        def _download_search_azure(key: str) -> int:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp_name = tmp.name
            try:
                logging.info(f"Downloading azure://{account_name}/{container_name}/{key} to {tmp_name}")
                blob_client = container_client.get_blob_client(key)
                with open(tmp_name, "wb") as my_blob:
                    blob_data = blob_client.download_blob()
                    blob_data.readinto(my_blob)

                matched = self.search.search_file(
                    tmp_name,
                    key,
                    query,
                    hide_filenames,
                    yara_rules,
                    log_format,
                    log_properties,
                    json_output,
                    account_name,
                )
                return 1 if matched else 0
            except ResourceNotFoundError:
                logging.info(f"File {key} not found in {account_name}/{container_name}")
                return 0
            except Exception as e:
                logging.error(f"Error downloading or searching {key}: {e}")
                return 0
            finally:
                try:
                    os.remove(tmp_name)
                except OSError:
                    pass

        return self._download_and_search_in_parallel(files, _download_search_azure)

    def download_from_google(
        self,
        bucket: str,
        files: List[str],
        query: List[str],
        hide_filenames: bool,
        yara_rules: Any,
        log_format: Optional[str] = None,
        log_properties: Optional[List[str]] = None,
        json_output: bool = False,
    ) -> int:
        """Download every file in the bucket from google
        Returns number of matched files"""
        if not log_properties:
            log_properties = []

        client = storage.Client()
        bucket_gcp = client.get_bucket(bucket)

        def _download_and_search_google(key: str) -> int:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp_name = tmp.name
            try:
                logging.info(f"Downloading gs://{bucket}/{key} to {tmp_name}")
                blob = bucket_gcp.get_blob(key)
                if blob is None:
                    logging.warning(f"Blob not found: {key}")
                    return 0
                blob.download_to_filename(tmp_name)

                matched = self.search.search_file(
                    tmp_name, key, query, hide_filenames, yara_rules, log_format, log_properties, json_output
                )
                return 1 if matched else 0
            except Exception as e:
                logging.error(f"Error downloading or searching {key}: {e}")
                return 0
            finally:
                try:
                    os.remove(tmp_name)
                except OSError:
                    pass

        return self._download_and_search_in_parallel(files, _download_and_search_google)

    def filter_object(
        self,
        obj: dict,
        key_contains: Optional[str],
        from_date: Optional[datetime],
        to_date: Optional[datetime],
        file_size: int,
    ) -> bool:
        """Filter S3 objects by date range, file size, and substring in key."""
        last_modified = obj["LastModified"]
        if last_modified and from_date and from_date > last_modified:
            return False  # Object was modified before the from_date
        if last_modified and to_date and last_modified > to_date:
            return False  # Object was modified after the to_date
        if obj["Size"] == 0 or int(obj["Size"]) > file_size:
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
        """Filter Azure blob objects similarly."""
        last_modified = obj["last_modified"]  # type: ignore
        if last_modified and from_date and from_date > last_modified:
            return False
        if last_modified and to_date and last_modified > to_date:
            return False
        if obj["size"] == 0 or int(obj["size"]) > file_size:
            return False
        if key_contains and key_contains not in obj["name"]:
            return False
        return True

    def filter_object_google(
        self,
        obj: storage.blob.Blob,
        key_contains: Optional[str],
        from_date: Optional[datetime],
        to_date: Optional[datetime],
    ) -> bool:
        """Filter objects in GCP"""
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
        """Get objects in S3"""
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
        """Get all objects in Azure storage container with a given prefix"""
        default_credential = DefaultAzureCredential()
        blob_service_client = BlobServiceClient.from_connection_string(
            f"DefaultEndpointsProtocol=https;AccountName={account_name};EndpointSuffix=core.windows.net",
            credential=default_credential,
        )
        container_client = blob_service_client.get_container_client(container_name)
        blobs = container_client.list_blobs(name_starts_with=prefix)

        for blob in blobs:
            if self.filter_object_azure(blob, key_contains, from_date, end_date, file_size):
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
            if self.filter_object_google(blob, key_contains, from_date, end_date):
                yield blob.name
