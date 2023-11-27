import tempfile
import re
from typing import List
import logging
import gzip
import zipfile
import os
import yara


class Search:
    def init(self) -> None:
        # Statically compile yara so we only have to compile it once
        yara.compile(filepaths={"yara_rules.yar": "yara_rules.yar"})

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

    def search_line(key_name: str, search: str, hide_filenames: bool, line: str) -> bool:
        """Regex search of the line"""
        if re.search(search, line):
            if not hide_filenames:
                print(f"{key_name}: {line}")
            else:
                print(line)
            return True
        return False

    def search_file(self, file_name: str, key_name: str, search: str, hide_filenames: bool) -> bool:
        """Regex search of the file line by line"""
        matched = False
        logging.info(f"Searching {file_name} for {search}")
        if key_name.endswith(".gz"):
            with gzip.open(file_name, "rt") as f:
                for line in f:
                    matched = self.search_line(key_name, search, hide_filenames, line)
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
                                    matched = self.search_line(key_name + "/" + filename, search, hide_filenames, line)
        else:
            for line in self.get_all_strings_line(file_name):
                if re.search(search, line):
                    matched = self.search_line(key_name, search, hide_filenames, line)

        return matched

    def yara_scan_file(self, file_name: str, key_name: str, yara_rules: str, hide_filenames: bool) -> bool:
        """Yara scan of the file"""
        matched = False
        logging.info(f"Yara scanning {file_name} for {yara_rules}")
        global YARA_RULES
        matches = YARA_RULES.match(file_name)
        if matches:
            for match in matches:
                if not hide_filenames:
                    print(f"{key_name}: {match.rule} : {match.strings}")
                else:
                    print(f"{match.rule} : {match.strings}")
                matched = True
        return matched
