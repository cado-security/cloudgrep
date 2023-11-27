import boto3
from datetime import timezone, datetime
from dateutil.parser import parse
from typing import Optional
import logging
from cloudgrep.cloud import Cloud
import yara


class CloudGrep:
    def load_queries(self, file: str) -> str:
        """Load in a list of queries from a file"""
        with open(file, "r") as f:
            return "|".join([line.strip() for line in f.readlines() if len(line.strip())])

    def search(
        self,
        bucket: Optional[str],
        account_name: Optional[str],
        container_name: Optional[str],
        google_bucket: Optional[str],
        query: str,
        file: Optional[str],
        yara_file: Optional[str],
        file_size: int,
        prefix: Optional[str] = None,
        key_contains: Optional[str] = None,
        from_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        hide_filenames: bool = False,
        profile: Optional[str] = None,
    ) -> None:
        # load in a list of queries from a file
        if not query and file:
            logging.info(f"Loading queries in from {file}")
            query = self.load_queries(file)

        if yara_file:
            logging.info(f"Loading yara rules from {yara_file}")
            yara_rules = yara.compile(filepath=yara_file)
        else:
            yara_rules = None

        if profile:
            # Set the AWS credentials profile to use
            boto3.setup_default_session(profile_name=profile)

        # Parse dates
        parsed_from_date = None
        if from_date:
            parsed_from_date = parse(from_date).astimezone(timezone.utc)  # type: ignore
        parsed_end_date = None
        if end_date:
            parsed_end_date = parse(end_date).astimezone(timezone.utc)  # type: ignore

        if bucket:
            matching_keys = list(
                Cloud().get_objects(bucket, prefix, key_contains, parsed_from_date, parsed_end_date, file_size)
            )
            s3_client = boto3.client("s3")
            region = s3_client.get_bucket_location(Bucket=bucket)
            print(
                f"Bucket is in region: {region['LocationConstraint']} : Search from the same region to avoid egress charges."
            )
            print(f"Searching {len(matching_keys)} files in {bucket} for {query}...")
            Cloud().download_from_s3_multithread(bucket, matching_keys, query, hide_filenames, yara_rules)

        if account_name and container_name:
            matching_keys = list(
                Cloud().get_azure_objects(
                    account_name, container_name, prefix, key_contains, parsed_from_date, parsed_end_date, file_size
                )
            )
            print(f"Searching {len(matching_keys)} files in {account_name}/{container_name} for {query}...")
            Cloud().download_from_azure(account_name, container_name, matching_keys, query, hide_filenames, yara_rules)

        if google_bucket:
            matching_keys = list(
                Cloud().get_google_objects(google_bucket, prefix, key_contains, parsed_from_date, parsed_end_date)
            )

            print(f"Searching {len(matching_keys)} files in {google_bucket} for {query}...")

            Cloud().download_from_google(google_bucket, matching_keys, query, hide_filenames, yara_rules)
