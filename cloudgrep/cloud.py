import boto3
import os
try:
    from azure.storage.blob import BlobServiceClient
    from azure.identity import DefaultAzureCredential
    from azure.core.exceptions import ResourceNotFoundError
except Exception:  # pragma: no cover - optional dependency
    BlobServiceClient = None
    DefaultAzureCredential = None

    class ResourceNotFoundError(Exception):
        pass
try:
    from google.cloud import storage  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    storage = None

from datetime import datetime
import botocore
import concurrent.futures
import tempfile
from typing import Iterator, Optional, List, Any, Tuple
import logging
from cloudgrep.search import Search
from pytz import timezone


class _GCSBlobStub:
    def __init__(self, name: str, bucket: Optional[str] = None, updated: Optional[datetime] = None) -> None:
        self.name = name
        self.bucket = bucket
        self.updated = updated


class _GCSStorageStub:
    class blob:
        Blob = _GCSBlobStub

    class Client:
        def __init__(self, *_: Any, **__: Any) -> None:
            raise ImportError("google-cloud-storage is required for GCS operations")


if storage is None:
    storage = _GCSStorageStub()


if BlobServiceClient is None:
    class BlobServiceClient:  # type: ignore[no-redef]
        @classmethod
        def from_connection_string(cls, *_: Any, **__: Any) -> "BlobServiceClient":
            raise ImportError("azure-storage-blob is required for Azure operations")


if DefaultAzureCredential is None:
    class DefaultAzureCredential:  # type: ignore[no-redef]
        def __init__(self, *_: Any, **__: Any) -> None:
            # Allow tests to mock Azure clients without the dependency installed.
            pass
class Cloud:
    def __init__(self) -> None:
        self.search = Search()

    def _download_and_search_in_parallel(self, files: List[Any], worker_func: Any) -> int:
        """Use ThreadPoolExecutor to download every file
        Returns number of matched files"""
        total_matched = 0
        max_workers = 10 # limit cpu/memory pressure
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            for result in executor.map(worker_func, files):
                total_matched += result
        return total_matched

    def _download_to_temp(self) -> str:
        """Return a temporary filename"""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.close()
            return tmp.name

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
        convert_date: bool = False,
        use_og_name : bool = False
    ) -> int:
        """Download and search files from AWS S3"""
        if log_properties is None:
            log_properties = []
        s3 = boto3.client("s3", config=botocore.config.Config(max_pool_connections=64))

        def _download_search_s3(key: str) -> int:
            tmp_name = self._download_to_temp()
            try:
                logging.info(f"Downloading s3://{bucket}/{key} to {tmp_name}")
                s3.download_file(bucket, key, tmp_name)
                og_name = key if use_og_name else tmp_name
                matched = self.search.search_file(
                    tmp_name, key, query, hide_filenames, yara_rules, log_format, log_properties, json_output, convert_date=convert_date, og_name=og_name
                )
                return 1 if matched else 0
            except Exception:
                logging.exception(f"Error processing {key}")
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
        """Download and search files from Azure Storage"""
        if log_properties is None:
            log_properties = []
        default_credential = DefaultAzureCredential()
        connection_str = f"DefaultEndpointsProtocol=https;AccountName={account_name};EndpointSuffix=core.windows.net"
        blob_service_client = BlobServiceClient.from_connection_string(connection_str, credential=default_credential)
        container_client = blob_service_client.get_container_client(container_name)

        def _download_search_azure(key: str) -> int:
            tmp_name = self._download_to_temp()
            try:
                logging.info(f"Downloading azure://{account_name}/{container_name}/{key} to {tmp_name}")
                blob_client = container_client.get_blob_client(key)
                with open(tmp_name, "wb") as out_file:
                    stream = blob_client.download_blob()
                    stream.readinto(out_file)
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
            except Exception:
                logging.exception(f"Error processing {key}")
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
        blobs: List[Tuple[str, Any]],
        query: List[str],
        hide_filenames: bool,
        yara_rules: Any,
        log_format: Optional[str] = None,
        log_properties: Optional[List[str]] = None,
        json_output: bool = False,
    ) -> int:
        """Download and search files from Google Cloud Storage"""
        if log_properties is None:
            log_properties = []

        def _download_and_search_google(item: Tuple[str, Any]) -> int:
            key, blob = item
            tmp_name = self._download_to_temp()
            try:
                logging.info(f"Downloading gs://{bucket}/{key} to {tmp_name}")
                blob.download_to_filename(tmp_name)
                matched = self.search.search_file(
                    tmp_name, key, query, hide_filenames, yara_rules, log_format, log_properties, json_output
                )
                return 1 if matched else 0
            except Exception:
                logging.exception(f"Error processing {key}")
                return 0
            finally:
                try:
                    os.remove(tmp_name)
                except OSError:
                    pass

        return self._download_and_search_in_parallel(blobs, _download_and_search_google)

    def get_objects(
        self,
        bucket: str,
        prefix: Optional[str],
        key_contains: Optional[str],
        from_date: Optional[datetime],
        end_date: Optional[datetime],
        file_size: int,
        max_matches: int = 1000000, # generous default
        convert_date: bool = False,
    ) -> Iterator[str]:
        """Yield a maximum of max_matches objects that match filter"""
        # Reuse the S3 client if already created; otherwise, create one
        if not hasattr(self, "s3_client"):
            self.s3_client = boto3.client("s3")
        paginator = self.s3_client.get_paginator("list_objects_v2")
        count = 0
        for page in paginator.paginate(
            Bucket=bucket,
            Prefix=prefix,
            PaginationConfig={'PageSize': 1000}
        ):
            for obj in page.get("Contents", []):
                if self.filter_object(obj, key_contains, from_date, end_date, file_size, convert_date=convert_date):
                    yield obj.get("Key")
                    count += 1
                    if count >= max_matches:
                        return

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
        """Yield Azure blob names that match the filter"""
        default_credential = DefaultAzureCredential()
        connection_str = f"DefaultEndpointsProtocol=https;AccountName={account_name};EndpointSuffix=core.windows.net"
        blob_service_client = BlobServiceClient.from_connection_string(connection_str, credential=default_credential)
        container_client = blob_service_client.get_container_client(container_name)
        for blob in container_client.list_blobs(name_starts_with=prefix):
            if self.filter_object_azure(blob, key_contains, from_date, end_date, file_size):
                yield blob.name

    def get_google_objects(
        self,
        bucket: str,
        prefix: Optional[str],
        key_contains: Optional[str],
        from_date: Optional[datetime],
        end_date: Optional[datetime],
    ) -> Iterator[Tuple[str, Any]]:
        """Yield (blob_name, blob) for blobs in GCP that match filter"""
        client = storage.Client()
        bucket_gcp = client.get_bucket(bucket)
        for blob in bucket_gcp.list_blobs(prefix=prefix):
            if self.filter_object_google(blob, key_contains, from_date, end_date):
                yield blob.name, blob

    def filter_object(
        self,
        obj: dict,
        key_contains: Optional[str],
        from_date: Optional[datetime],
        to_date: Optional[datetime],
        file_size: int,
        convert_date: bool = False,
    ) -> bool:
        """Filter an S3 object based on modification date, size, and key substring"""
        last_modified = obj.get("LastModified")
        # Fix error : "TypeError: can't compare offset-naive and offset-aware datetimes"
        if convert_date:
            from_date = from_date.astimezone(timezone("UTC")) if from_date else None
            to_date = to_date.astimezone(timezone("UTC")) if to_date else None
            # Convert last_modified to UTC if it's not already
            if isinstance(last_modified, datetime):
                last_modified = last_modified.astimezone(timezone("UTC"))
        if last_modified:
            if from_date and last_modified < from_date:
                return False
            if to_date and last_modified > to_date:
                return False
        # If size is 0 or greater than file_size, skip
        if int(obj.get("Size", 0)) == 0 or int(obj.get("Size", 0)) > file_size:
            return False
        if key_contains and key_contains not in obj.get("Key", ""):
            return False
        return True

    def filter_object_azure(
        self,
        obj: Any,
        key_contains: Optional[str],
        from_date: Optional[datetime],
        to_date: Optional[datetime],
        file_size: int,
    ) -> bool:
        """
        Filter an Azure blob object (or dict) based on modification date, size, and name substring.
        """
        if isinstance(obj, dict):
            last_modified = obj.get("last_modified")
            size = int(obj.get("size", 0))
            name = obj.get("name", "")
        else:
            last_modified = getattr(obj, "last_modified", None)
            size = int(getattr(obj, "size", 0))
            name = getattr(obj, "name", "")
        if last_modified:
            if from_date and last_modified < from_date:
                return False
            if to_date and last_modified > to_date:
                return False
        if size == 0 or size > file_size:
            return False
        if key_contains and key_contains not in name:
            return False
        return True

    def filter_object_google(
        self,
        obj: storage.blob.Blob,
        key_contains: Optional[str],
        from_date: Optional[datetime],
        to_date: Optional[datetime],
    ) -> bool:
        """Filter a GCP blob based on update time and name substring"""
        last_modified = getattr(obj, "updated", None)
        if last_modified:
            if from_date and last_modified < from_date:
                return False
            if to_date and last_modified > to_date:
                return False
        if key_contains and key_contains not in getattr(obj, "name", ""):
            return False
        return True
