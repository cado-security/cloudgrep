import tempfile
import re
from typing import List, Any
import logging
import gzip
import zipfile
import os


class Search:
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

    def search_line(self, key_name: str, search: str, hide_filenames: bool, line: str) -> bool:
        """Regex search of the line"""
        if re.search(search, line):
            if not hide_filenames:
                print(f"{key_name}: {line}")
            else:
                print(line)
            return True
        return False

    def yara_scan_file(self, file_name: str, key_name: str, hide_filenames: bool, yara_rules: Any) -> bool:  # type: ignore
        matched = False
        matches = yara_rules.match(file_name)
        if matches:
            for match in matches:
                if not hide_filenames:
                    print(f"{key_name}: {match.rule} : {match.strings}")
                else:
                    print(f"{match.rule} : {match.strings}")
                matched = True
        return matched

    def search_file(self, file_name: str, key_name: str, search: str, hide_filenames: bool, yara_rules: Any) -> bool:
        """Regex search of the file line by line"""
        matched = False
        logging.info(f"Searching {file_name} for {search}")

        if yara_rules:
            matched = self.yara_scan_file(file_name, key_name, hide_filenames, yara_rules)
        else:
            if key_name.endswith(".gz"):
                with gzip.open(file_name, "rt") as f:
                    for line in f:
                        if self.search_line(key_name, search, hide_filenames, line):
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
                                        if self.search_line("{key_name}/{filename}", search, hide_filenames, line):
                                            matched = True
            else:
                for line in self.get_all_strings_line(file_name):
                    if self.search_line(key_name, search, hide_filenames, line):
                        matched = True

        return matched
