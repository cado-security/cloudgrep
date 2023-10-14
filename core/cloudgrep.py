import boto3
from azure.storage.blob import BlobServiceClient
from azure.identity import DefaultAzureCredential
from azure.core.exceptions import ResourceNotFoundError
from datetime import timezone, datetime
from dateutil.parser import parse
import botocore
import concurrent
import tempfile
import re
from typing import Iterator, Optional, List
import logging
import gzip
import zipfile
import os

class CloudGrep:
    def get_all_strings_line(self, file_path: str) -> List[str]:
        """Get all the strings from a file line by line
        We do this instead of f.readlines() as this supports binary files too
        """
        with open(file_path, "rb") as f:
            read_bytes = f.read()
            b = read_bytes.decode("utf-8", "ignore")
            b = b.replace("\n", "\r")
            string_list = b.split("\r")
            return string_list

    def search_file(self, file_name: str, key_name: str, search: str, hide_filenames: bool) -> bool:
        """Regex search of the file line by line"""
        matched = False
        logging.info(f"Searching {file_name} for {search}")
        if key_name.endswith(".gz"):
            with gzip.open(file_name, "rt") as f:
                for line in f:
                    if re.search(search, line):
                        print(f"{key_name}: {line}")
                        matched = True
        elif key_name.endswith(".zip"):
            with tempfile.TemporaryDirectory() as tempdir:
                with zipfile.ZipFile(file_name, "r") as zf:
                    zf.extractall(tempdir)
                    logging.info(f"Extracted {file_name} to {tempdir}")
                    for filename in os.listdir(tempdir):
                        logging.info(f"Searching in zip {filename}")
                        if os.path.isfile(os.path.join(tempdir, filename)):
                            with open(os.path.join(tempdir, filename)) as f:
                                for line in f:
                                    if re.search(search, line):
                                        print(f"{key_name}/{filename}: {line}")
                                        matched = True
        else:
            for line in self.get_all_strings_line(file_name):
                if re.search(search, line):
                    if not hide_filenames:
                        print(f"{key_name}: {line}")
                    else:
                        print(line)
                    matched = True

        return matched

    def download_from_s3_multithread(self, bucket: str, files: List[str], query: str, hide_filenames: bool) -> int:
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
                logging.info(f"Downloading {bucket} {key} to {tmp.name}")
                s3.download_file(bucket, key, tmp.name)
                matched = self.search_file(tmp.name, key, query, hide_filenames)
                if matched:
                    nonlocal matched_count
                    matched_count += 1

        # Use ThreadPoolExecutor to download the files
        with concurrent.futures.ThreadPoolExecutor() as executor:  # type: ignore
            executor.map(download_file, files)
        return matched_count

    def download_from_azure(self, account_name: str, container_name: str, files: List[str], query: str, hide_filenames: bool) -> int:
        """ Download every file in the container from azure
        Returns number of matched files"""
        default_credential = DefaultAzureCredential()
        matched_count = 0
        blob_service_client = BlobServiceClient.from_connection_string(
            f"DefaultEndpointsProtocol=https;AccountName={account_name};EndpointSuffix=core.windows.net",
            credential=default_credential
        )
        container_client = blob_service_client.get_container_client(container_name)

        def download_file(key: str) -> None:
            with tempfile.NamedTemporaryFile() as tmp:
                logging.info(f"Downloading {account_name}/{container_name} {key} to {tmp.name}")
                try:
                    blob_client = container_client.get_blob_client(key)
                    with open(tmp.name, "wb") as my_blob:
                        blob_data = blob_client.download_blob()
                        blob_data.readinto(my_blob)
                    matched = self.search_file(tmp.name, key, query, hide_filenames)
                    if matched:
                        nonlocal matched_count
                        matched_count += 1
                except ResourceNotFoundError:
                    logging.info(f"File {key} not found in {account_name}/{container_name}")

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
        obj: dict,
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
            credential=default_credential
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

    def search(
        self,
        bucket: Optional[str],
        account_name: Optional[str],
        container_name: Optional[str],
        query: str,
        file_size: int,
        prefix: Optional[str] = None,
        key_contains: Optional[str] = None,
        from_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        hide_filenames: bool = False,
    ) -> None:
        
        # Parse dates
        parsed_from_date = None
        if from_date:
            parsed_from_date = parse(from_date).astimezone(timezone.utc)  # type: ignore
        parsed_end_date = None
        if end_date:
            parsed_end_date = parse(end_date).astimezone(timezone.utc)  # type: ignore
        

        if bucket:
            matching_keys = list(
            self.get_objects(bucket, prefix, key_contains, parsed_from_date, parsed_end_date, file_size)
            )
            s3_client = boto3.client("s3")
            region = s3_client.get_bucket_location(Bucket=bucket)
            print(
                f"Bucket is in region: {region['LocationConstraint']} : Search from the same region to avoid egress charges."
            )
            print(f"Searching {len(matching_keys)} files in {bucket} for {query}...")
            self.download_from_s3_multithread(bucket, matching_keys, query, hide_filenames)

        if account_name and container_name:
            matching_keys = list(
                self.get_azure_objects(account_name, container_name, prefix, key_contains, parsed_from_date, parsed_end_date, file_size)
            )
            print(f"Searching {len(matching_keys)} files in {account_name}/{container_name} for {query}...")
            self.download_from_azure(account_name, container_name, matching_keys, query, hide_filenames)
