"""
Basic unit tests for Cloud Grep
python3 -m unittest discover tests
"""

import unittest
import os
import boto3
from google.cloud import storage  # type: ignore
import timeout_decorator
from moto import mock_aws
from datetime import datetime
from unittest.mock import patch, MagicMock
import yara  # type: ignore
from io import StringIO
from typing import List, BinaryIO
import json
import sys
import csv

from cloudgrep.cloud import Cloud
from cloudgrep.search import Search
from cloudgrep.cloudgrep import CloudGrep


BASE_PATH = os.path.dirname(os.path.realpath(__file__))


class CloudGrepTests(unittest.TestCase):
    """Tests for Cloud Grep"""

    def test_weird_files(self) -> None:
        for filename in os.listdir(f"{BASE_PATH}/data/"):
            # Just checks we don't crash on any files
            Search().get_all_strings_line(f"{BASE_PATH}/data/" + filename)

        self.assertIn("SomeLine", Search().get_all_strings_line(f"{BASE_PATH}/data/14_3.log"))

    def test_gzip(self) -> None:
        found = Search().search_file(f"{BASE_PATH}/data/000000.gz", "000000.gz", ["Running on machine"], False, None)
        self.assertTrue(found)

    def test_zip(self) -> None:
        found = Search().search_file(f"{BASE_PATH}/data/000000.zip", "000000.zip", ["Running on machine"], False, None)
        self.assertTrue(found)

    def test_print_match(self) -> None:
        with patch("sys.stdout", new=StringIO()) as fake_out:
            Search().search_file(f"{BASE_PATH}/data/000000.zip", "000000.zip", ["Running on machine"], False, None)
            output = fake_out.getvalue().strip()
        self.assertIn("Running on machine", output)

    @timeout_decorator.timeout(5)
    @mock_aws
    def test_e2e(self) -> None:
        # This test uploads a couple of logs to mock s3
        # Then searches them
        _BUCKET = "mybucket"
        _QUERY = ["SomeLine"]

        conn = boto3.resource("s3", region_name="us-east-1")
        conn.create_bucket(Bucket=_BUCKET)
        s3 = boto3.client("s3", region_name="us-east-1")

        # All contain "SomeLine"
        for file_name in ["14_3.log", "35010_7.log", "apache_access.log"]:
            with open(f"{BASE_PATH}/data/{file_name}", "rb") as data:
                s3.upload_fileobj(data, _BUCKET, file_name)

        print("Checking we include every file")
        matching_keys = list(Cloud().get_objects(_BUCKET, "", None, None, None, 100000))
        self.assertEqual(len(matching_keys), 3)

        print(f"Checking we get 3 hits for SomeLine in: {matching_keys}")
        hits = Cloud().download_from_s3_multithread(_BUCKET, matching_keys, _QUERY, False, None)
        self.assertEqual(hits, 3)

        print("Testing with multiple queries from a file")
        file = "queries.txt"
        with open(file, "w") as f:
            f.write(f"query1\n{_QUERY}\nquery3")
        multi_query = CloudGrep().load_queries(file)
        hits = Cloud().download_from_s3_multithread(_BUCKET, matching_keys, multi_query, False, None)
        self.assertEqual(hits, 3)

        # Upload 1000 logs
        for x in range(1000):
            with open(f"{BASE_PATH}/data/apache_access.log", "rb") as data:
                s3.upload_fileobj(data, _BUCKET, str(x))

        Cloud().download_from_s3_multithread(_BUCKET, matching_keys, _QUERY, False, None)

    def test_object_not_empty_and_size_greater_than_file_size(self) -> None:
        obj = {"last_modified": datetime(2022, 1, 1), "size": 1000, "name": "example_file.txt"}
        key_contains = "example"
        from_date = datetime(2021, 1, 1)
        to_date = datetime(2023, 1, 1)
        file_size = 500
        result = Cloud().filter_object_azure(obj, key_contains, from_date, to_date, file_size)  # type: ignore
        self.assertFalse(result)
        file_size = 500000
        result = Cloud().filter_object_azure(obj, key_contains, from_date, to_date, file_size)  # type: ignore
        self.assertTrue(result)

    def test_returns_true_if_all_conditions_are_met(self) -> None:
        obj = storage.blob.Blob(name="example_file.txt", bucket="example_bucket")
        key_contains = "example"
        from_date = datetime(2021, 1, 1)
        to_date = datetime(2023, 1, 1)
        result = Cloud().filter_object_google(obj, key_contains, from_date, to_date)
        self.assertTrue(result)

    def test_returns_string_with_file_contents(self) -> None:
        file = "queries.txt"
        with open(file, "w") as f:
            f.write("query1\nquery2\nquery3")
        queries = CloudGrep().load_queries(file)
        self.assertIsInstance(queries, List)
        self.assertEqual(queries, ["query1", "query2", "query3"])

    def test_yara(self) -> None:
        file_name = "valid_file.txt"
        key_name = "key_name"
        hide_filenames = True
        yara_rules = yara.compile(source='rule rule_name {strings: $a = "get" nocase wide ascii condition: $a}')
        with open(file_name, "w") as f:
            f.write("one\nget stuff\nthree")

        with patch("sys.stdout", new=StringIO()) as fake_out:
            matched = Search().yara_scan_file(file_name, key_name, hide_filenames, yara_rules, True)
            output = fake_out.getvalue().strip()

        self.assertTrue(matched)
        self.assertEqual(output, "{'match_rule': 'rule_name', 'match_strings': [$a]}")

    def test_json_output(self) -> None:
        with patch("sys.stdout", new=StringIO()) as fake_out:
            Search().search_file(
                f"{BASE_PATH}/data/000000.gz", "000000.gz", ["Running on machine"], False, None, None, [], True
            )
            output = fake_out.getvalue().strip()

        self.assertTrue(json.loads(output))

    def test_search_cloudtrail(self) -> None:
        log_format = "json"
        log_properties = ["Records"]
        Search().search_file(
            f"{BASE_PATH}/data/bad_cloudtrail.json",
            "bad_cloudtrail.json",
            ["Running on machine"],
            False,
            None,
            log_format,
            log_properties,
        )
        Search().search_file(
            f"{BASE_PATH}/data/cloudtrail.json",
            "cloudtrail.json",
            ["Running on machine"],
            False,
            None,
            log_format,
            log_properties,
        )
        with patch("sys.stdout", new=StringIO()) as fake_out:
            Search().search_file(
                f"{BASE_PATH}/data/cloudtrail_singleline.json",
                "cloudtrail_singleline.json",
                ["SignatureVersion"],
                False,
                None,
                log_format,
                log_properties,
                True,
            )
            output = fake_out.getvalue().strip()
        self.assertIn("SignatureVersion", output)
        self.assertTrue(json.loads(output))

    def test_filter_object_s3_empty_file(self) -> None:
        obj = {"LastModified": datetime(2023, 1, 1), "Size": 0, "Key": "empty_file.log"}
        key_contains = "empty"
        from_date = datetime(2022, 1, 1)
        to_date = datetime(2024, 1, 1)
        file_size = 10000
        self.assertFalse(
            Cloud().filter_object(obj, key_contains, from_date, to_date, file_size),
            "Empty file should have been filtered out",
        )

    def test_filter_object_s3_out_of_date_range(self) -> None:
        obj = {"LastModified": datetime(2021, 1, 1), "Size": 500, "Key": "old_file.log"}
        key_contains = "old"
        from_date = datetime(2022, 1, 1)
        to_date = datetime(2024, 1, 1)
        file_size = 10000
        self.assertFalse(
            Cloud().filter_object(obj, key_contains, from_date, to_date, file_size),
            "Object older than from_date should not match",
        )

    def test_search_logs_csv_format(self) -> None:
        line = "col1,col2\nval1,val2"
        mock_return = [{"col1": "val1", "col2": "val2"}]
        with patch.object(csv, "DictReader", return_value=mock_return):
            with patch("sys.stdout", new=StringIO()) as fake_out:
                Search().search_logs(
                    line,
                    key_name="test_csv",
                    search="val1",
                    hide_filenames=False,
                    log_format="csv",
                    log_properties=[],
                    json_output=False,
                )
        self.assertIn("val1", fake_out.getvalue())

    def test_search_logs_unknown_format(self) -> None:
        line = '{"foo": "bar"}'
        with patch("sys.stdout", new=StringIO()):
            with patch("logging.error") as mock_log:
                Search().search_logs(
                    line,
                    key_name="unknown_format.log",
                    search="bar",
                    hide_filenames=False,
                    log_format="not_a_real_format",
                    log_properties=[],
                    json_output=False,
                )
        mock_log.assert_called_once()

    @mock_aws
    def test_cloudgrep_search_no_query_file(self) -> None:
        s3 = boto3.resource("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="mybucket")
        with open("small.log", "w") as f:
            f.write("hello direct query")
        with open("small.log", "rb") as data:
            s3.Bucket("mybucket").put_object(Key="small.log", Body=data)

        cg = CloudGrep()
        with patch("sys.stdout", new=StringIO()) as fake_out:
            cg.search(
                bucket="mybucket",
                account_name=None,
                container_name=None,
                google_bucket=None,
                query=["hello"],
                file=None,
                yara_file=None,
                file_size=1000000,
                prefix="",
                key_contains=None,
                from_date=None,
                end_date=None,
                hide_filenames=False,
                log_type=None,
                log_format=None,
                log_properties=[],
                profile=None,
                json_output=False,
            )
            output = fake_out.getvalue().strip()
            self.assertIn("hello direct query", output)

    @mock_aws
    def test_cloudgrep_search_with_profile(self) -> None:
        s3 = boto3.resource("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="prof-bucket")
        with open("small.log", "w") as f:
            f.write("Hello test profile")
        with open("small.log", "rb") as data:
            s3.Bucket("prof-bucket").put_object(Key="small.log", Body=data)

        with patch("boto3.setup_default_session") as mock_setup_session:
            cg = CloudGrep()
            cg.search(
                bucket="prof-bucket",
                account_name=None,
                container_name=None,
                google_bucket=None,
                query=["Hello"],
                file=None,
                yara_file=None,
                file_size=1000000,
                prefix="",
                key_contains=None,
                from_date=None,
                end_date=None,
                hide_filenames=False,
                log_type=None,
                log_format=None,
                log_properties=[],
                profile="my_aws_profile",
                json_output=False,
            )
            mock_setup_session.assert_called_with(profile_name="my_aws_profile")

    def test_main_no_args_shows_help(self) -> None:
        from cloudgrep.__main__ import main

        with patch.object(sys, "argv", ["prog"]):
            # Argparse prints help to sys.stderr
            with patch("sys.stderr", new=StringIO()) as fake_err:
                with self.assertRaises(SystemExit):
                    main()
                self.assertIn("usage: prog", fake_err.getvalue())

    @patch("cloudgrep.cloud.BlobServiceClient.from_connection_string")
    def test_azure_search_mocked(self, mock_service_client: MagicMock) -> None:
        # Mock azure client to do basic azure test

        container_client = MagicMock()
        mock_service_client.return_value.get_container_client.return_value = container_client

        blob_mock = MagicMock()
        blob_mock.name = "testblob.log"
        blob_mock.size = 50
        blob_mock.last_modified = datetime(2022, 1, 1)
        container_client.list_blobs.return_value = [blob_mock]

        blob_client_mock = MagicMock()
        container_client.get_blob_client.return_value = blob_client_mock

        # Actually written to a local file
        fake_content = b"Some Azure log entry that mentions azure target"

        def fake_readinto_me(file_obj: BinaryIO) -> None:
            file_obj.write(fake_content)

        blob_data_mock = MagicMock()
        blob_data_mock.readinto.side_effect = fake_readinto_me
        blob_client_mock.download_blob.return_value = blob_data_mock

        with patch("sys.stdout", new=StringIO()) as fake_out:
            CloudGrep().search(
                bucket=None,
                account_name="fakeaccount",
                container_name="fakecontainer",
                google_bucket=None,
                query=["azure target"],  # Our search term
                file=None,
                yara_file=None,
                file_size=1000000,
                prefix=None,
                key_contains=None,
                from_date=None,
                end_date=None,
                hide_filenames=False,
                log_type=None,
                log_format=None,
                log_properties=[],
                profile=None,
                json_output=False,
            )
            output = fake_out.getvalue().strip()

        # Check in fake file
        self.assertIn("azure target", output, "Should match the azure target text in the downloaded content")

    @patch("cloudgrep.cloud.storage.Client")
    def test_google_search_mocked(self, mock_storage_client: MagicMock) -> None:
        # Basic coverage for gcp search
        bucket_mock = MagicMock()
        mock_storage_client.return_value.get_bucket.return_value = bucket_mock

        blob_mock = MagicMock()
        blob_mock.name = "test_gcs_file.log"
        blob_mock.updated = datetime(2023, 1, 1)
        bucket_mock.list_blobs.return_value = [blob_mock]

        def fake_download_to_filename(local_path: str) -> None:
            with open(local_path, "wb") as f:
                f.write(b"This is some fake file: google target")

        blob_mock.download_to_filename.side_effect = fake_download_to_filename

        with patch("sys.stdout", new=StringIO()) as fake_out:
            CloudGrep().search(
                bucket=None,
                account_name=None,
                container_name=None,
                google_bucket="fake-gcs-bucket",
                query=["google target"],
                file=None,
                yara_file=None,
                file_size=1000000,
                prefix=None,
                key_contains=None,
                from_date=None,
                end_date=None,
                hide_filenames=False,
                log_type=None,
                log_format=None,
                log_properties=[],
                profile=None,
                json_output=False,
            )
            output = fake_out.getvalue().strip()

        self.assertIn("google target", output, "Should match the google target text in the downloaded content")

    @mock_aws
    def test_list_files_returns_pre_filtered_files(self) -> None:
        """
        Test that list_files() returns only the S3 objects that match
        the specified filters (e.g. key substring and non‑empty content).
        """
        bucket_name = "list-files-test-bucket"
        # Create a fake S3 bucket
        s3_resource = boto3.resource("s3", region_name="us-east-1")
        s3_resource.create_bucket(Bucket=bucket_name)
        s3_client = boto3.client("s3", region_name="us-east-1")
        
        # Upload several objects:
        # - Two objects that match
        s3_client.put_object(Bucket=bucket_name, Key="log_file1.txt", Body=b"dummy content")
        s3_client.put_object(Bucket=bucket_name, Key="log_file2.txt", Body=b"dummy content")
        # Onne that doesnt match the key_contains filter
        s3_client.put_object(Bucket=bucket_name, Key="not_a_thing.txt", Body=b"dummy content")
        # One that doesnt match the file_size filter
        s3_client.put_object(Bucket=bucket_name, Key="log_empty.txt", Body=b"")

        # Call list files
        cg = CloudGrep()
        result = cg.list_files(
            bucket=bucket_name,
            account_name=None,
            container_name=None,
            google_bucket=None,
            prefix="",
            key_contains="log",
            from_date=None,
            end_date=None,
            file_size=1000000  # 1 MB
        )

        # Assert only the matching files are returned
        self.assertIn("s3", result)
        expected_keys = {"log_file1.txt", "log_file2.txt"}
        self.assertEqual(set(result["s3"]), expected_keys)

        # Now search the contents of the files and assert they hit
        for key in expected_keys:
            with patch("sys.stdout", new=StringIO()) as fake_out:
                cg.search(
                    bucket=bucket_name,
                    account_name=None,
                    container_name=None,
                    google_bucket=None,
                    query=["dummy content"],
                    file=None,
                    yara_file=None,
                    file_size=1000000,
                    prefix="",
                    key_contains=key,
                    from_date=None,
                    end_date=None,
                    hide_filenames=False,
                    log_type=None,
                    log_format=None,
                    log_properties=[],
                    profile=None,
                    json_output=False,
                    files=result, # Pass the pre-filtered files from list_files
                )
                output = fake_out.getvalue().strip()
            self.assertIn("log_file1.txt", output)