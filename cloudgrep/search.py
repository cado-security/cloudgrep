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

    def search_file(self, file_name: str, key_name: str, search: str, hide_filenames: bool) -> bool:
        """Regex search of the file line by line"""
        matched = False
        logging.info(f"Searching {file_name} for {search}")
        if key_name.endswith(".gz"):
            with gzip.open(file_name, "rt") as f:
                for line in f:
                    if re.search(search, line):
                        print(f"{key_name}: {line}")
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
                                    if re.search(search, line):
                                        print(f"{key_name}/{filename}: {line}")
                                        matched = True
        else:
            for line in self.get_all_strings_line(file_name):
                if re.search(search, line):
                    if not hide_filenames:
                        print(f"{key_name}: {line}")
                    else:
                        print(line)
                    matched = True

        return matched

    def yara_scan_file(self, file_name: str, key_name: str, yara_rules: str, hide_filenames: bool) -> bool:
        """Yara scan of the file"""
        matched = False
        logging.info(f"Yara scanning {file_name} for {yara_rules}")
        rules = yara.compile(source=yara_rules)
        matches = rules.match(file_name)
        if matches:
            for match in matches:
                if not hide_filenames:
                    print(f"{key_name}: {match}")
                else:
                    print(match)
                matched = True
        return matched