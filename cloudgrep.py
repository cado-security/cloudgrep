from core.cloudgrep import CloudGrep
import argparse
import logging

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CloudGrep searches is grep for cloud storage like S3.")
    parser.add_argument("-b", "--bucket", help="AWS S3 Bucket to search. E.g. my-bucket", required=False)
    parser.add_argument("-an", "--account-name", help="Azure Account Name to Search", required=False)
    parser.add_argument("-cn", "--container-name", help="Azure Container Name to Search", required=False)
    parser.add_argument(
        "-q", "--query", help="Text to search for. Will be parsed as a Regex. E.g. example.com", required=True
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
        required=False,
    )
    parser.add_argument("-d", "--debug", help="Enable Debug logging. ", action="store_true", required=False)
    parser.add_argument(
        "-hf", "--hide_filenames", help="Dont show matching filesnames. ", action="store_true", required=False
    )
    args = vars(parser.parse_args())

    if args["debug"]:
        logging.basicConfig(format="[%(asctime)s]:[%(levelname)s] - %(message)s", level=logging.INFO)

    CloudGrep().search(
        args["bucket"],
        args["account_name"],
        args["container_name"],
        args["query"],
        args["prefix"],
        args["filename"],
        args["start_date"],
        args["end_date"],
        args["file_size"],
        args["hide_filenames"],
    )
