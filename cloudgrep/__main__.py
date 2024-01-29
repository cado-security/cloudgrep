import argparse
import logging
import sys
from typing import List

from cloudgrep.cloudgrep import CloudGrep

VERSION = "1.0.5"

# Define a custom argument type for a list of strings
def list_of_strings(arg: str) -> List[str]:
    return arg.split(",")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"CloudGrep searches is grep for cloud storage like S3 and Azure Storage. Version: {VERSION}"
    )
    parser.add_argument("-b", "--bucket", help="AWS S3 Bucket to search. E.g. my-bucket", required=False)
    parser.add_argument("-an", "--account-name", help="Azure Account Name to Search", required=False)
    parser.add_argument("-cn", "--container-name", help="Azure Container Name to Search", required=False)
    parser.add_argument("-gb", "--google-bucket", help="Google Cloud Bucket to Search", required=False)
    parser.add_argument(
        "-q",
        "--query",
        type=list_of_strings,
        help="Text to search for. Will be parsed as a Regex. E.g. example.com",
        required=False,
    )
    parser.add_argument(
        "-v",
        "--file",
        help="File containing a list of words or regular expressions to search for. One per line.",
        required=False,
    )
    parser.add_argument(
        "-y",
        "--yara",
        help="File containing Yara rules to scan files.",
        required=False,
    )
    parser.add_argument(
        "-p",
        "--prefix",
        help="Optionally filter on the start of the Object name. E.g. logs/",
        required=False,
        default="",
    )
    parser.add_argument(
        "-f", "--filename", help="Optionally filter on Objects that match a keyword. E.g. .log.gz ", required=False
    )
    parser.add_argument(
        "-s",
        "--start_date",
        help="Optionally filter on Objects modified after a Date or Time. E.g. 2022-01-01 ",
        required=False,
    )
    parser.add_argument(
        "-e",
        "--end_date",
        help="Optionally filter on Objects modified before a Date or Time. E.g. 2022-01-01 ",
        required=False,
    )
    parser.add_argument(
        "-fs",
        "--file_size",
        help="Optionally filter on Objects smaller than a file size, in bytes. Defaults to 100 Mb. ",
        default=100000000,
        required=False,
    )
    parser.add_argument(
        "-pr",
        "--profile",
        help="Set an AWS profile to use. E.g. default, dev, prod.",
        required=False,
    )
    parser.add_argument("-d", "--debug", help="Enable Debug logging. ", action="store_true", required=False)
    parser.add_argument(
        "-hf", "--hide_filenames", help="Dont show matching filenames. ", action="store_true", required=False
    )
    parser.add_argument(
        "-lt",
        "--log_type",
        help="Return individual matching log entries based on pre-defined log types, otherwise custom log_format and log_properties can be used. E.g. cloudtrail. ",
        required=False,
    )
    parser.add_argument(
        "-lf",
        "--log_format",
        help="Define custom log format of raw file to parse before applying search logic. Used if --log_type is not defined. E.g. json. ",
        required=False,
    )
    parser.add_argument(
        "-lp",
        "--log_properties",
        type=list_of_strings,
        help="Define custom list of properties to traverse to dynamically extract final list of log records. Used if --log_type is not defined. E.g. ["
        "Records"
        "]. ",
        required=False,
    )
    parser.add_argument("-jo", "--json_output", help="Output as JSON.", action="store_true")
    args = vars(parser.parse_args())

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args["debug"]:
        logging.basicConfig(format="[%(asctime)s]:[%(levelname)s] - %(message)s", level=logging.INFO)
    else:
        logging.basicConfig(format="[%(asctime)s] - %(message)s", level=logging.WARNING)
        logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)

    CloudGrep().search(
        args["bucket"],
        args["account_name"],
        args["container_name"],
        args["google_bucket"],
        args["query"],
        args["file"],
        args["yara"],
        int(args["file_size"]),
        args["prefix"],
        args["filename"],
        args["start_date"],
        args["end_date"],
        args["hide_filenames"],
        args["log_type"],
        args["log_format"],
        args["log_properties"],
        args["profile"],
        args["json_output"],
    )


if __name__ == "__main__":
    main()
