import re
from typing import Optional, List, Any, Iterator, Iterable
import logging
import gzip
import zipfile
import json
import csv
import io

class Search:
    def get_all_strings_line(self, file_path: str) -> Iterator[str]:
        """Yield lines from a file without loading into memory"""
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                yield line

    def print_match(self, match_info: dict, hide_filenames: bool, json_output: Optional[bool]) -> None:
        output = match_info.copy()
        if hide_filenames:
            output.pop("key_name", None)
        if json_output:
            try:
                print(json.dumps(output))
            except TypeError:
                print(str(output))
        else:
            line = output.get("line", "")
            if "match_rule" in output:
                line = f"{output['match_rule']}: {output.get('match_strings', '')}"
            print(f"{output.get('key_name', '')}: {line}" if not hide_filenames else line)

    def parse_logs(self, line: str, log_format: Optional[str]) -> Any:
        if log_format == "json":
            try:
                return json.loads(line)
            except json.JSONDecodeError as e:
                logging.error(f"JSON decode error in line: {line} ({e})")
        elif log_format == "csv":
            try:
                return list(csv.DictReader([line]))
            except csv.Error as e:
                logging.error(f"CSV parse error in line: {line} ({e})")
        elif log_format:
            logging.error(f"Unsupported log format: {log_format}")
        return None

    def extract_log_entries(self, parsed: Any, log_properties: List[str]) -> List[Any]:
        if log_properties and isinstance(parsed, dict):
            for prop in log_properties:
                parsed = parsed.get(prop, None)
                if parsed is None:
                    break
        if isinstance(parsed, list):
            return parsed
        elif parsed is not None:
            return [parsed]
        return []

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
        parsed = self.parse_logs(line, log_format)
        if not parsed:
            return
        for entry in self.extract_log_entries(parsed, log_properties):
            entry_str = json.dumps(entry)
            if re.search(search, entry_str):
                self.print_match({"key_name": key_name, "query": search, "line": entry}, hide_filenames, json_output)

    def search_line(
        self,
        key_name: str,
        compiled_patterns: List[re.Pattern],
        hide_filenames: bool,
        line: str,
        log_format: Optional[str],
        log_properties: List[str] = [],
        json_output: Optional[bool] = False,
    ) -> bool:
        """Regex search of the line"""
        found = False
        for regex in compiled_patterns:
            if regex.search(line):
                if log_format:
                    self.search_logs(line, key_name, regex.pattern, hide_filenames, log_format, log_properties, json_output)
                else:
                    self.print_match(
                        {"key_name": key_name, "query": regex.pattern, "line": line}, hide_filenames, json_output
                    )
                found = True
        return found

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
        patterns: List[str],
        hide_filenames: bool,
        yara_rules: Any,
        log_format: Optional[str] = None,
        log_properties: List[str] = [],
        json_output: Optional[bool] = False,
        account_name: Optional[str] = None,
    ) -> bool:
        """Regex search of the file line by line"""
        logging.info(f"Searching {file_name} for patterns: {patterns}")
        if yara_rules:
            return self.yara_scan_file(file_name, key_name, hide_filenames, yara_rules, json_output)
        
        compiled_patterns = [re.compile(p) for p in patterns]

        def process_lines(lines: Iterable[str]) -> bool:
            return any(
                self.search_line(key_name, compiled_patterns, hide_filenames, line, log_format, log_properties, json_output)
                for line in lines
            )

        if file_name.endswith(".gz"):
            try:
                with gzip.open(file_name, "rt", encoding="utf-8", errors="ignore") as f:
                    if account_name:
                        data = json.load(f)
                        return process_lines(data)
                    else:
                        return process_lines(f)
            except Exception:
                logging.exception(f"Error processing gzip file: {file_name}")
                return False
        elif file_name.endswith(".zip"):
            matched_any = False
            try:
                with zipfile.ZipFile(file_name, "r") as zf:
                    for zip_info in zf.infolist():
                        if zip_info.is_dir():
                            continue
                        with zf.open(zip_info) as file_obj:
                            # Wrap the binary stream as text
                            with io.TextIOWrapper(file_obj, encoding="utf-8", errors="ignore") as f:
                                if account_name:
                                    try:
                                        data = json.load(f)
                                        if process_lines(data):
                                            matched_any = True
                                    except Exception:
                                        logging.exception(f"Error processing json in zip member: {zip_info.filename}")
                                else:
                                    if process_lines(f):
                                        matched_any = True
                return matched_any
            except Exception:
                logging.exception(f"Error processing zip file: {file_name}")
                return False
        else:
            try:
                return process_lines(self.get_all_strings_line(file_name))
            except Exception:
                logging.exception(f"Error processing file: {file_name}")
                return False
