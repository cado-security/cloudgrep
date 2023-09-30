"""
Basic unit tests for Cloud Grep
python3 -m unittest discover tests
"""
import unittest
import os
import boto3
import timeout_decorator
from moto import mock_s3

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
        matching_keys = list(CloudGrep().get_objects(_BUCKET, "", None, None, None, 0))
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
