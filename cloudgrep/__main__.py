import argparse
import logging
import sys
from typing import List, Optional
import dateutil.parser
import datetime

from cloudgrep.cloudgrep import CloudGrep

VERSION = "1.0.5"


def list_of_strings(arg: str) -> List[str]:
    """Parse a comma‐separated string into a list of nonempty strings."""
    return [s.strip() for s in arg.split(",") if s.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"CloudGrep: grep for cloud storage (S3, Azure, Google Cloud). Version: {VERSION}"
    )
    parser.add_argument("-b", "--bucket", help="AWS S3 Bucket to search (e.g. my-bucket)")
    parser.add_argument("-an", "--account-name", help="Azure Account Name to search")
    parser.add_argument("-cn", "--container-name", help="Azure Container Name to search")
    parser.add_argument("-gb", "--google-bucket", help="Google Cloud Bucket to search")
    parser.add_argument("-q", "--query", type=list_of_strings, help="Comma-separated list of regex patterns to search")
    parser.add_argument("-v", "--file", help="File containing queries (one per line)")
    parser.add_argument("-y", "--yara", help="File containing Yara rules")
    parser.add_argument("-p", "--prefix", default="", help="Filter objects by prefix (e.g. logs/)")
    parser.add_argument("-f", "--filename", help="Filter objects whose names contain a keyword (e.g. .log.gz)")
    parser.add_argument("-s", "--start_date", help="Filter objects modified after this date (YYYY-MM-DD)")
    parser.add_argument("-e", "--end_date", help="Filter objects modified before this date (YYYY-MM-DD)")
    parser.add_argument(
        "-fs",
        "--file_size",
        type=int,
        default=100_000_000,
        help="Max file size in bytes (default: 100MB)",
    )
    parser.add_argument("-pr", "--profile", help="AWS profile to use (e.g. default, dev, prod)")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("-hf", "--hide_filenames", action="store_true", help="Hide filenames in output")
    parser.add_argument("-lt", "--log_type", help="Pre-defined log type (e.g. cloudtrail, azure)")
    parser.add_argument("-lf", "--log_format", help="Custom log format (e.g. json, csv)")
    parser.add_argument(
        "-lp", "--log_properties", type=list_of_strings, help="Comma-separated list of log properties to extract"
    )
    parser.add_argument("-jo", "--json_output", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    # Parse dates (if provided) into datetime objects
    start_date: Optional["datetime.datetime"] = dateutil.parser.parse(args.start_date) if args.start_date else None
    end_date: Optional["datetime.datetime"] = dateutil.parser.parse(args.end_date) if args.end_date else None

    # Configure logging
    if args.debug:
        logging.basicConfig(format="[%(asctime)s] [%(levelname)s] %(message)s", level=logging.DEBUG)
    else:
        logging.basicConfig(format="[%(asctime)s] %(message)s", level=logging.WARNING)
        logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)

    CloudGrep().search(
        bucket=args.bucket,
        account_name=args.account_name,
        container_name=args.container_name,
        google_bucket=args.google_bucket,
        query=args.query,
        file=args.file,
        yara_file=args.yara,
        file_size=args.file_size,
        prefix=args.prefix,
        key_contains=args.filename,
        from_date=start_date,
        end_date=end_date,
        hide_filenames=args.hide_filenames,
        log_type=args.log_type,
        log_format=args.log_format,
        log_properties=args.log_properties,
        profile=args.profile,
        json_output=args.json_output,
    )


if __name__ == "__main__":
    main()
