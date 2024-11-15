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
            b = read_bytes.decode("utf-8", "ignore")
            b = b.replace("\n", "\r")
            string_list = b.split("\r")
            return string_list
    def print_match(self, matched_line_dict: dict, hide_filenames: bool, json_output: Optional[bool]) -> None:
        """Print matched line"""
        if json_output:
            if hide_filenames:
                matched_line_dict.pop("key_name")
            try:

                print(json.dumps(matched_line_dict))
            except TypeError:

                print(str(matched_line_dict))
        else:
            line = ""
            if "line" in matched_line_dict:
                line = matched_line_dict["line"]
            if "match_rule" in matched_line_dict:
                line = f"{matched_line_dict['match_rule']}: {matched_line_dict['match_strings']}"

            if not hide_filenames:
                print(f"{matched_line_dict['key_name']}: {line}")
            else:
                print(line)

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
        """Regex search of each log record in input line"""
        # Parse input line based on defined format.
        match log_format:
            case "json":
                try:
                    line_parsed = json.loads(line)
                except json.JSONDecodeError:
                    logging.error(f"Invalid JSON in line: {line}")
                    return None
            case "csv":
                line_parsed = csv.DictReader(line)
            case _:
                logging.error(
                    f"Invalid log_format value ('{log_format}') in switch statement in 'search_logs' function, so defaulting to 'json'."
                )
                # Default to JSON format.
                log_format = "json"
                line_parsed = json.loads(line)
        # Step into property/properties to get to final list of lines for per-line searching.
        if log_properties != None:
            for log_property in log_properties:
                if line_parsed:
                    line_parsed = line_parsed.get(log_property, None)

        # Ensure line_parsed is iterable.
        if type(line_parsed) != list:
            line_parsed = [line_parsed]

        # Perform per-line searching.
        for record in line_parsed:
            if re.search(search, json.dumps(record)):
                matched_line_dict = {"key_name": key_name, "query": search, "line": record}
                self.print_match(matched_line_dict, hide_filenames, json_output)

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
        matched = False
        for cur_search in search:
            if re.search(cur_search, line):
                if log_format != None:
                    self.search_logs(
                        line, key_name, cur_search, hide_filenames, log_format, log_properties, json_output
                    )
                else:
                    matched_line_dict = {"key_name": key_name, "query": cur_search, "line": line}
                    self.print_match(matched_line_dict, hide_filenames, json_output)
                matched = True
        return matched

    def yara_scan_file(self, file_name: str, key_name: str, hide_filenames: bool, yara_rules: Any, json_output: Optional[bool] = False) -> bool:  # type: ignore
        matched = False
        matches = yara_rules.match(file_name)
        if matches:
            for match in matches:
                matched_line_dict = {"key_name": key_name, "match_rule": match.rule, "match_strings": match.strings}
                self.print_match(matched_line_dict, hide_filenames, json_output)
                matched = True
        return matched

    def search_file(
        self,
        file_name: str,
        key_name: str,
        search: List[str],
        hide_filenames: bool,
        yara_rules: Any,
        log_type: Optional[str] = None,
        log_format: Optional[str] = None,
        log_properties: List[str] = [],
        json_output: Optional[bool] = False,
        account_name: Optional[str] = None,
    ) -> bool:
        """Regex search of the file line by line"""
        matched = False

        logging.info(f"Searching {file_name} for {search}")
        if yara_rules:
            matched = self.yara_scan_file(file_name, key_name, hide_filenames, yara_rules, json_output)
        else:
            if key_name.endswith(".gz"):
                with gzip.open(file_name, "rt") as f:
                    if log_type == 'azure' or log_type == 'gcp':
                        try:
                            data = json.load(f)
                            line = json.dumps(data)  
                                                                
                            if self.search_line(
                                key_name, search, hide_filenames, line, log_format, log_properties, json_output
                            ):
                                matched = True
                        except json.JSONDecodeError:
                            logging.info(f"File {file_name} is not JSON")
                    else:
                        for line in f:
                            if self.search_line(
                               key_name, search, hide_filenames, line, log_format, log_properties, json_output
                         ):
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
                                
                                    if log_type == 'azure':
                                       
                                        try:
                                            data = json.load(f)
                                            line = json.dumps(data)                                           
                                            if self.search_line(
                                                key_name, search, hide_filenames, line, log_format, log_properties, json_output
                                            ):
                                                matched = True
                                        except json.JSONDecodeError:
                                            logging.info(f"File {file_name} is not JSON")
                                    elif log_type == 'gcp':
                                       # print("test")
                                        data = json.load(f)
                                        line = json.dumps(data)
                                        # for line in f:
                                        if self.search_line(
                                            key_name,
                                            search,
                                            hide_filenames,
                                            line,
                                            log_format,
                                            log_properties,
                                            json_output,
                                        ):
                                            matched = True
                                    else:          
                                        for line in f:
                                            if self.search_line(
                                                f"{key_name}/{filename}",
                                                search,
                                                hide_filenames,
                                                line,
                                                log_format,
                                                log_properties,
                                                json_output,
                                            ):
                                                matched = True
            else:
                if log_format == 'json':
                      with open(file_name, "r") as f:
                        data = json.load(f)
                        line = json.dumps(data)
                        
                        if self.search_line(
                            key_name, search, hide_filenames, line, log_format, log_properties, json_output
                        ):
                            matched = True
                else:

                    for line in self.get_all_strings_line(file_name):
                        if self.search_line(
                            key_name, search, hide_filenames, line, log_format, log_properties, json_output
                        ):
                            matched = True

        return matched
