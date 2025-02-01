import boto3
from datetime import datetime
from typing import Optional, List, Any
import logging
import yara  # type: ignore

from cloudgrep.cloud import Cloud


class CloudGrep:
    def __init__(self) -> None:
        self.cloud = Cloud()

    def load_queries(self, file_path: str) -> List[str]:
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    def search(
        self,
        bucket: Optional[str],
        account_name: Optional[str],
        container_name: Optional[str],
        google_bucket: Optional[str],
        query: Optional[List[str]],
        file: Optional[str],
        yara_file: Optional[str],
        file_size: int,
        prefix: Optional[str] = None,
        key_contains: Optional[str] = None,
        from_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        hide_filenames: bool = False,
        log_type: Optional[str] = None,
        log_format: Optional[str] = None,
        log_properties: Optional[List[str]] = None,
        profile: Optional[str] = None,
        json_output: bool = False,
    ) -> None:
        if not query and file:
            logging.debug(f"Loading queries from {file}")
            query = self.load_queries(file)
        if not query:
            logging.error("No query provided. Exiting.")
            return

        yara_rules = None
        if yara_file:
            logging.debug(f"Compiling yara rules from {yara_file}")
            yara_rules = yara.compile(filepath=yara_file)

        if profile:
            boto3.setup_default_session(profile_name=profile)

        if log_type:
            if log_type.lower() == "cloudtrail":
                log_format = "json"
                log_properties = ["Records"]
            elif log_type.lower() == "azure":
                log_format = "json"
                log_properties = ["data"]
            else:
                logging.error(f"Invalid log_type: {log_type}")
                return
        if log_properties is None:
            log_properties = []

        if bucket:
            self._search_s3(
                bucket,
                query,
                yara_rules,
                file_size,
                prefix,
                key_contains,
                from_date,
                end_date,
                hide_filenames,
                log_format,
                log_properties,
                json_output,
            )
        if account_name and container_name:
            self._search_azure(
                account_name,
                container_name,
                query,
                yara_rules,
                file_size,
                prefix,
                key_contains,
                from_date,
                end_date,
                hide_filenames,
                log_format,
                log_properties,
                json_output,
            )
        if google_bucket:
            self._search_gcs(
                google_bucket,
                query,
                yara_rules,
                file_size,
                prefix,
                key_contains,
                from_date,
                end_date,
                hide_filenames,
                log_format,
                log_properties,
                json_output,
            )

    def _search_s3(
        self,
        bucket: str,
        query: List[str],
        yara_rules: Any,
        file_size: int,
        prefix: Optional[str],
        key_contains: Optional[str],
        from_date: Optional[datetime],
        end_date: Optional[datetime],
        hide_filenames: bool,
        log_format: Optional[str],
        log_properties: List[str],
        json_output: bool,
    ) -> None:
        """ Search S3 bucket for query """
        matching_keys = list(self.cloud.get_objects(bucket, prefix, key_contains, from_date, end_date, file_size))
        s3_client = boto3.client("s3")
        region = s3_client.get_bucket_location(Bucket=bucket).get("LocationConstraint", "unknown")
        logging.warning(f"Bucket region: {region}. (Search from the same region to avoid egress charges.)")
        logging.warning(f"Searching {len(matching_keys)} files in {bucket} for {query}...")
        self.cloud.download_from_s3_multithread(
            bucket, matching_keys, query, hide_filenames, yara_rules, log_format, log_properties, json_output
        )

    def _search_azure(
        self,
        account_name: str,
        container_name: str,
        query: List[str],
        yara_rules: Any,
        file_size: int,
        prefix: Optional[str],
        key_contains: Optional[str],
        from_date: Optional[datetime],
        end_date: Optional[datetime],
        hide_filenames: bool,
        log_format: Optional[str],
        log_properties: List[str],
        json_output: bool,
    ) -> None:
        matching_keys = list(
            self.cloud.get_azure_objects(
                account_name, container_name, prefix, key_contains, from_date, end_date, file_size
            )
        )
        logging.info(f"Searching {len(matching_keys)} files in {account_name}/{container_name} for {query}...")
        self.cloud.download_from_azure(
            account_name,
            container_name,
            matching_keys,
            query,
            hide_filenames,
            yara_rules,
            log_format,
            log_properties,
            json_output,
        )

    def _search_gcs(
        self,
        google_bucket: str,
        query: List[str],
        yara_rules: Any,
        file_size: int,
        prefix: Optional[str],
        key_contains: Optional[str],
        from_date: Optional[datetime],
        end_date: Optional[datetime],
        hide_filenames: bool,
        log_format: Optional[str],
        log_properties: List[str],
        json_output: bool,
    ) -> None:
        # Get (blob_name, blob)
        matching_blobs = list(self.cloud.get_google_objects(google_bucket, prefix, key_contains, from_date, end_date))
        logging.info(f"Searching {len(matching_blobs)} files in {google_bucket} for {query}...")
        self.cloud.download_from_google(
            google_bucket, matching_blobs, query, hide_filenames, yara_rules, log_format, log_properties, json_output
        )
