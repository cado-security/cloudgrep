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
    def get_all_strings_line(self, file_path: str) -> List[str]:
        """Get all the strings from a file line by line
        We do this instead of f.readlines() as this supports binary files too
        """
        with open(file_path, "rb") as f:
            read_bytes = f.read()
            return read_bytes.decode("utf-8", "ignore").replace("\n", "\r").split("\r")

    def print_match(self, matched_line_dict: dict, hide_filenames: bool, json_output: Optional[bool]) -> None:
        """Print matched line"""
        if json_output:
            matched_line_dict.pop("key_name", None) if hide_filenames else None
            try:
                print(json.dumps(matched_line_dict))
            except TypeError:
                print(str(matched_line_dict))
        else:
            line = matched_line_dict.get("line", "")
            if "match_rule" in matched_line_dict:
                line = f"{matched_line_dict['match_rule']}: {matched_line_dict['match_strings']}"
            print(line if hide_filenames else f"{matched_line_dict['key_name']}: {line}")

    def parse_logs(self, line: str, log_format: Optional[str]) -> Any:
        """Parse input log line based on format"""
        try:
            if log_format == "json":
                return json.loads(line)
            elif log_format == "csv":
                return list(csv.DictReader([line]))
            elif log_format:
                logging.error(f"Invalid log format: {log_format}")
        except (json.JSONDecodeError, csv.Error) as e:
            logging.error(f"Invalid {log_format} format in line: {line} ({e})")
        return None

    def extract_log_entries(self, line_parsed: Any, log_properties: List[str]) -> List[Any]:
        """Extract properties in log entries"""
        if log_properties:
            for log_property in log_properties:
                if isinstance(line_parsed, dict):
                    line_parsed = line_parsed.get(log_property, None)
        return line_parsed if isinstance(line_parsed, list) else [line_parsed]

    def search_logs(
        self,
        line: str,
        key_name: str,
        search: str,
        hide_filenames: bool,
        log_format: Optional[str] = None,
        log_properties: List[str] = [],
        json_output: Optional[bool] = False,
    ) -> None:
        """Search log records in parsed logs"""
        line_parsed = self.parse_logs(line, log_format)
        if not line_parsed:
            return

        for record in self.extract_log_entries(line_parsed, log_properties):
            if re.search(search, json.dumps(record)):
                self.print_match({"key_name": key_name, "query": search, "line": record}, hide_filenames, json_output)

    def search_line(
        self,
        key_name: str,
        search: List[str],
        hide_filenames: bool,
        line: str,
        log_format: Optional[str],
        log_properties: List[str] = [],
        json_output: Optional[bool] = False,
    ) -> bool:
        """Regex search of the line"""
        matched = any(re.search(cur_search, line) for cur_search in search)
        if matched:
            if log_format:
                for cur_search in search:
                    self.search_logs(
                        line, key_name, cur_search, hide_filenames, log_format, log_properties, json_output
                    )
            else:
                self.print_match({"key_name": key_name, "query": search, "line": line}, hide_filenames, json_output)
        return matched

    def yara_scan_file(
        self, file_name: str, key_name: str, hide_filenames: bool, yara_rules: Any, json_output: Optional[bool] = False
    ) -> bool:
        """Run Yara scan on a file"""
        matches = yara_rules.match(file_name)
        for match in matches:
            self.print_match(
                {"key_name": key_name, "match_rule": match.rule, "match_strings": match.strings},
                hide_filenames,
                json_output,
            )
        return bool(matches)

    def search_file(
        self,
        file_name: str,
        key_name: str,
        search: List[str],
        hide_filenames: bool,
        yara_rules: Any,
        log_format: Optional[str] = None,
        log_properties: List[str] = [],
        json_output: Optional[bool] = False,
        account_name: Optional[str] = None,
    ) -> bool:
        """Regex search of the file line by line"""
        logging.info(f"Searching {file_name} for {search}")
        if yara_rules:
            return self.yara_scan_file(file_name, key_name, hide_filenames, yara_rules, json_output)

        def process_lines(lines) -> bool:
            return any(
                self.search_line(key_name, search, hide_filenames, line, log_format, log_properties, json_output)
                for line in lines
            )

        if key_name.endswith(".gz"):
            with gzip.open(file_name, "rt") as f:
                return process_lines(json.load(f) if account_name else f)
        elif key_name.endswith(".zip"):
            with tempfile.TemporaryDirectory() as tempdir, zipfile.ZipFile(file_name, "r") as zf:
                zf.extractall(tempdir)
                return any(
                    # Process the extracted files
                    process_lines(
                        json.load(open(os.path.join(tempdir, filename)))
                        if account_name
                        else open(os.path.join(tempdir, filename))
                    )
                    # Search all files in the zip file
                    for filename in os.listdir(tempdir)
                    if os.path.isfile(os.path.join(tempdir, filename))
                )
        return process_lines(self.get_all_strings_line(file_name))
