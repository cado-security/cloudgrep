import tempfile
import re
from typing import Optional, List, Any
import logging
import gzip
import zipfile
import os
import json
import csv

class Search:
    def get_all_strings_line(self, file_path: str) -> list[str]:
        """Get all the strings from a file line by line
        We do this instead of f.readlines() as this supports binary files too
        """
        with open(file_path, "rb") as f:
            read_bytes = f.read()
            b = read_bytes.decode("utf-8", "ignore")
            b = b.replace("\n", "\r")
            string_list = b.split("\r")
            return string_list

    def search_logs(
        self,
        line: str,
        key_name: str,
        search: str,
        hide_filenames: bool,
        log_format: str,
        log_properties: Optional[list[str]] = None,
    ):
        """Regex search of each log record in input line"""
        # Parse input line based on defined format.
        match log_format:
            case "json":
                line_parsed = json.loads(line)
            case "csv":
                line_parsed = csv.DictReader(line)
            case _:
                logging.error(f"Invalid log_format value ('{log_format}') in switch statement in 'search_logs' function, so defaulting to 'json'.")
                # Default to JSON format.
                log_format = "json"
                line_parsed = json.loads(line)

        # Step into property/properties to get to final list of lines for per-line searching.
        if log_properties != None:
            for log_property in log_properties:
                line_parsed = line_parsed[log_property]

        # Ensure line_parsed is iterable.
        if type(line_parsed) != list:
            line_parsed = [line_parsed]

        # Perform per-line searching.
        for record in line_parsed:
            if re.search(search, json.dumps(record)):
                matched_line_dict = {
                    "key_name": key_name,
                    "line" : record
                }
                if hide_filenames:
                    matched_line_dict.pop("key_name")
                print(json.dumps(matched_line_dict))
    
    def search_line(
        self,
        key_name: str,
        search: str,
        hide_filenames: bool,
        line: str,
        log_format: str,
        log_properties: Optional[list[str]] = None,
    ) -> bool:
        """Regex search of the line"""
        if re.search(search, line):
            if log_format != None:
                self.search_logs(line, key_name, search, hide_filenames, log_format, log_properties)
            else:
                matched_line_dict = {
                    "key_name": key_name,
                    "line" : line
                }
                if hide_filenames:
                    matched_line_dict.pop("key_name")
                print(json.dumps(matched_line_dict))
            return True
        return False

    def yara_scan_file(self, file_name: str, key_name: str, hide_filenames: bool, yara_rules: Any) -> bool:  # type: ignore
        matched = False
        matches = yara_rules.match(file_name)
        if matches:
            for match in matches:
                matched_line_dict = {
                    "key_name": key_name,
                    "match_rule": match.rule,
                    "match_strings": match.strings
                }
                if not hide_filenames:
                    matched_line_dict.pop("key_name")
                print(json.dumps(matched_line_dict))
                matched = True
        return matched

    def search_file(
        self,
        file_name: str,
        key_name: str,
        search: str,
        hide_filenames: bool,
        yara_rules: Any,
        log_format: str,
        log_properties: Optional[list[str]] = None,
    ) -> bool:
        """Regex search of the file line by line"""
        matched = False
        logging.info(f"Searching {file_name} for {search}")

        if yara_rules:
            matched = self.yara_scan_file(file_name, key_name, hide_filenames, yara_rules)
        else:
            if key_name.endswith(".gz"):
                with gzip.open(file_name, "rt") as f:
                    for line in f:
                        if self.search_line(key_name, search, hide_filenames, line, log_format, log_properties):
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
                                        if self.search_line("{key_name}/{filename}", search, hide_filenames, line, log_format, log_properties):
                                            matched = True
            else:
                for line in self.get_all_strings_line(file_name):
                    if self.search_line(key_name, search, hide_filenames, line, log_format, log_properties):
                        matched = True

        return matched
