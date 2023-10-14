"""
Basic unit tests for Cloud Grep
python3 -m unittest discover tests
"""
import unittest
import os
import boto3
from google.cloud import storage
import timeout_decorator
from moto import mock_s3
from datetime import datetime

from core.cloudgrep import CloudGrep


class CloudGrepTests(unittest.TestCase):
    """Tests for Cloud Grep"""

    def test_true(self) -> None:
        self.assertEqual(1, 1)

    def test_weird_files(self) -> None:
        for filename in os.listdir("./tests/data/"):
            # Just checks we don't crash on any files
            CloudGrep().get_all_strings_line("./tests/data/" + filename)

        self.assertIn("SomeLine", CloudGrep().get_all_strings_line("./tests/data/14_3.log"))

    def test_gzip(self) -> None:
        # Get lines from .gz compressed file
        found = CloudGrep().search_file("./tests/data/000000.gz", "000000.gz", "Running on machine", False)
        self.assertTrue(found)

    def test_zip(self) -> None:
        # Get lines from .zip compressed file
        found = CloudGrep().search_file("./tests/data/000000.zip", "000000.zip", "Running on machine", False)
        self.assertTrue(found)

    @timeout_decorator.timeout(5)  # Normally takes around 3 seconds to run in github actions
    @mock_s3
    def test_e2e(self) -> None:
        # This test uploads a couple of logs to mock s3
        # Then searches them

        _BUCKET = "mybucket"
        _QUERY = "SomeLine"

        conn = boto3.resource("s3", region_name="us-east-1")
        conn.create_bucket(Bucket=_BUCKET)
        s3 = boto3.client("s3", region_name="us-east-1")

        for file_name in ["14_3.log", "35010_7.log", "apache_access.log"]:
            with open(f"./tests/data/{file_name}", "rb") as data:
                s3.upload_fileobj(data, _BUCKET, file_name)

        print("Checking we include every file")
        matching_keys = list(CloudGrep().get_objects(_BUCKET, "", None, None, None, 100000))
        print(f"Checking we include every file: {matching_keys}")
        assert len(matching_keys) == 3

        print(f"Checking we only get one search hit in: {matching_keys}")
        hits = CloudGrep().download_from_s3_multithread(_BUCKET, matching_keys, _QUERY, False)
        assert hits == 1

        # Upload a log 10 000 times and see how long it takes
        print("Uploading large number of logs")
        for x in range(1000):
            with open("./tests/data/apache_access.log", "rb") as data:
                s3.upload_fileobj(data, _BUCKET, str(x))

        print("Searching")
        CloudGrep().download_from_s3_multithread(_BUCKET, matching_keys, _QUERY, False)
        print("Searched")

    def test_object_not_empty_and_size_greater_than_file_size(self) -> None:
        # Object is not empty and its size is greater than or equal to the file_size parameter.
        obj = {"last_modified": datetime(2022, 1, 1), "size": 1000, "name": "example_file.txt"}
        key_contains = "example"
        from_date = datetime(2021, 1, 1)
        to_date = datetime(2023, 1, 1)
        file_size = 50000

        cloud_grep = CloudGrep()
        result = cloud_grep.filter_object_azure(obj, key_contains, from_date, to_date, file_size)  # type: ignore

        assert result == True

    # Returns True if all conditions are met
    def test_returns_true_if_all_conditions_are_met(self):
        obj = storage.blob.Blob(name="example_file.txt", bucket="example_bucket")
        key_contains = "example"
        from_date = datetime(2021, 1, 1)
        to_date = datetime(2023, 1, 1)
        file_size = 50000

        cloud_grep = CloudGrep()
        result = cloud_grep.filter_object_google(obj, key_contains, from_date, to_date, file_size)

        self.assertTrue(result)