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
from typing import List
import json
import sys
import argparse
import logging
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
        found = Search().search_file(
            f"{BASE_PATH}/data/000000.gz", "000000.gz", ["Running on machine"], False, None
        )
        self.assertTrue(found)

    def test_zip(self) -> None:
        found = Search().search_file(
            f"{BASE_PATH}/data/000000.zip", "000000.zip", ["Running on machine"], False, None
        )
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
        _QUERY = "SomeLine"

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

    def test_filter_object_s3_empty_file(self):
        obj = {
            "LastModified": datetime(2023, 1, 1),
            "Size": 0,
            "Key": "empty_file.log"
        }
        key_contains = "empty"
        from_date = datetime(2022, 1, 1)
        to_date = datetime(2024, 1, 1)
        file_size = 10000
        self.assertFalse(
            Cloud().filter_object(obj, key_contains, from_date, to_date, file_size),
            "Empty file should have been filtered out"
        )

    def test_filter_object_s3_out_of_date_range(self):
        obj = {
            "LastModified": datetime(2021, 1, 1),
            "Size": 500,
            "Key": "old_file.log"
        }
        key_contains = "old"
        from_date = datetime(2022, 1, 1)
        to_date = datetime(2024, 1, 1)
        file_size = 10000
        self.assertFalse(
            Cloud().filter_object(obj, key_contains, from_date, to_date, file_size),
            "Object older than from_date should not match"
        )

    def test_search_logs_csv_format(self):
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
                    json_output=False
                )
        self.assertIn("val1", fake_out.getvalue())

    def test_search_logs_unknown_format(self):
        line = '{"foo": "bar"}'
        with patch("sys.stdout", new=StringIO()) as fake_out:
            with patch("logging.error") as mock_log:
                Search().search_logs(
                    line,
                    key_name="unknown_format.log",
                    search="bar",
                    hide_filenames=False,
                    log_format="not_a_real_format",
                    log_properties=[],
                    json_output=False
                )
        mock_log.assert_called_once()

    @mock_aws
    def test_cloudgrep_search_no_query_file(self):
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
                json_output=False
            )
            output = fake_out.getvalue().strip()
            self.assertIn("hello direct query", output)

    @mock_aws
    def test_cloudgrep_search_with_profile(self):
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
                json_output=False
            )
            mock_setup_session.assert_called_with(profile_name="my_aws_profile")

    def test_main_no_args_shows_help(self):
        from cloudgrep.__main__ import main
        with patch.object(sys, "argv", ["prog"]):
            # Argparse prints help to sys.stderr
            with patch("sys.stderr", new=StringIO()) as fake_err:
                with self.assertRaises(SystemExit):
                    main()
                self.assertIn("usage: prog", fake_err.getvalue())


def test_search_azure(self) -> None:  # type: ignore
    log_format = "json"
    log_properties = ["data"]
    Search().search_file(
        f"{BASE_PATH}/data/bad_azure.json",
        "bad_azure.json",
        ["azure.gz"],
        False,
        None,
        log_format,
        log_properties,
    )
    Search().search_file(
        f"{BASE_PATH}/data/azure.json",
        "azure.json",
        ["azure.gz"],
        False,
        None,
        log_format,
        log_properties,
    )
    with patch("sys.stdout", new=StringIO()) as fake_out:
        Search().search_file(
            f"{BASE_PATH}/data/azure_singleline.json",
            "azure_singleline.json",
            ["azure.gz"],
            False,
            None,
            log_format,
            log_properties,
            True,
        )
        output = fake_out.getvalue().strip()
    self.assertIn("SignatureVersion", output)
    self.assertTrue(json.loads(output))
