import boto3
from datetime import timezone, datetime
from dateutil.parser import parse
from typing import Optional
import logging
from cloudgrep.cloud import Cloud
from typing import List

import yara  # type: ignore


class CloudGrep:
    def load_queries(self, file: str) -> List[str]:
        """Load in a list of queries from a file"""
        with open(file, "r") as f:
            return [line.strip() for line in f.readlines() if len(line.strip())]

    def search(
        self,
        bucket: Optional[str],
        account_name: Optional[str],
        container_name: Optional[str],
        google_bucket: Optional[str],
        query: List[str],
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
        log_properties: List[str] = [],
        profile: Optional[str] = None,
        json_output: Optional[bool] = False,
    ) -> None:
        # load in a list of queries from a file
        if not query and file:
            logging.debug(f"Loading queries in from {file}")
            query = self.load_queries(file)

        # Set log_format and log_properties values based on potential log_type input argument
        if log_type != None:
            match log_type:
                case "cloudtrail":
                    log_format = "json"
                    log_properties = ["Records"]
                case "azure":
                    log_format = "json"
                case "gcp":
                    log_format = "json"
    
                case _:
                    logging.error(
                        f"Invalid log_type value ('{log_type}') unhandled in switch statement in 'search' function."
                    )

        if yara_file:
            logging.debug(f"Loading yara rules from {yara_file}")
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
            if log_format != None:
                logging.warning(
                    f"Bucket is in region: {region['LocationConstraint']} : Search from the same region to avoid egress charges."
                )
                logging.warning(f"Searching {len(matching_keys)} files in {bucket} for {query}...")

            else:
                print(
                    f"Bucket is in region: {region['LocationConstraint']} : Search from the same region to avoid egress charges."
                )
                print(f"Searching {len(matching_keys)} files in {bucket} for {query}...")
            Cloud().download_from_s3_multithread(
                bucket, matching_keys, query, hide_filenames, yara_rules, log_type, log_format, log_properties, json_output
            )

        if account_name and container_name:
            matching_keys = list(
                Cloud().get_azure_objects(
                    account_name, container_name, prefix, key_contains, parsed_from_date, parsed_end_date, file_size
                )
            )
            print(f"Searching {len(matching_keys)} files in {account_name}/{container_name} for {query}...")

            Cloud().download_from_azure(
                account_name,
                container_name,
                matching_keys,
                query,
                hide_filenames,
                yara_rules,
                log_type,
                log_format,
                log_properties,
                json_output,
            )

        if google_bucket:
            matching_keys = list(
                Cloud().get_google_objects(google_bucket, prefix, key_contains, parsed_from_date, parsed_end_date)
            )

            print(f"Searching {len(matching_keys)} files in {google_bucket} for {query}...")

            Cloud().download_from_google(
                google_bucket, matching_keys, query, hide_filenames, yara_rules, log_type, log_format, log_properties, json_output
            )
