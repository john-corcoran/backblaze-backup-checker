#!/usr/bin/env python3

"""Diagnose null byte prevalence in bz_done log data"""

import argparse
import dataclasses
import datetime
import logging
import os
import pathlib
import platform
import typing


@dataclasses.dataclass
class NullRow:
    """Dataclass for records in bz_done containing null bytes"""

    content: str
    length: int
    row_position: int
    null_count: int
    null_locations: typing.List[int]


class MsgCounterHandler(logging.Handler):
    """Custom logging handler to count number of calls per log level"""

    def __init__(self, *args, **kwargs) -> None:
        super(MsgCounterHandler, self).__init__(*args, **kwargs)
        self.count = {}
        self.count["WARNING"] = 0
        self.count["ERROR"] = 0

    def emit(self, record) -> None:
        levelname = record.levelname
        if levelname not in self.count:
            self.count[levelname] = 0
        self.count[levelname] += 1


def _prepare_logging(
    datetime_string: str,
    write_logs: bool,
    folder_path: typing.Optional[str],
    identifier: str,
    args: typing.Dict[str, typing.Any],
    show_debug: bool = False,
    write_debug: bool = False,
) -> typing.Tuple[logging.Logger, MsgCounterHandler]:
    """Prepare and return logging object to be used throughout script"""
    log = logging.getLogger(__name__)
    log.setLevel(logging.DEBUG)
    # 'Quiet' logger for when quiet flag used in functions
    quiet = logging.getLogger("quiet")
    quiet.setLevel(logging.ERROR)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    if (write_logs or write_debug) and folder_path is not None:
        info_log = logging.FileHandler(
            os.path.join(folder_path, "{}_{}_info.log".format(datetime_string, identifier))
        )
        info_log.setLevel(logging.INFO)
        info_log.setFormatter(formatter)
        log.addHandler(info_log)
    if write_debug and folder_path is not None:
        debug_log = logging.FileHandler(
            os.path.join(folder_path, "{}_{}_debug.log".format(datetime_string, identifier))
        )
        debug_log.setLevel(logging.DEBUG)
        debug_log.setFormatter(formatter)
        log.addHandler(debug_log)
    console_handler = logging.StreamHandler()
    if show_debug:
        console_handler.setLevel(logging.DEBUG)
    else:
        console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    log.addHandler(console_handler)
    counter_handler = MsgCounterHandler()
    log.addHandler(counter_handler)
    # Log platform details and commandline arguments
    platform_detail_requests = [
        "python_version",
        "system",
        "machine",
        "platform",
        "version",
        "mac_ver",
    ]
    for platform_detail_request in platform_detail_requests:
        try:
            log.debug(
                "%s: %s", platform_detail_request, getattr(platform, platform_detail_request)()
            )
        except:  # pylint: disable=W0702
            pass
    log.debug("commandline_args: %s", args)
    return log, counter_handler


def get_file_paths_and_total_size(
    paths: typing.List[str],
    ignore_dotfiles: bool,
    ignore_windows_volume_folders: bool,
    log: typing.Optional[logging.Logger] = None,
) -> typing.Tuple[typing.List[str], int]:
    """Get list of file paths at a path (recurses subdirectories) and total size of directory"""
    if (
        log is None
    ):  # i.e. we are NOT calling from a separate process, so can get the logger ourself
        log = logging.getLogger(__name__)

    def walk_error(os_error: OSError) -> None:
        """Log any errors occurring during os.walk"""
        if log is not None:
            log.warning(
                "'%s' could not be accessed during folder scanning - any contents will not be"
                " processed. Try running script as admin",
                os_error.filename,
            )

    EXCLUDE_FOLDERS = {"$RECYCLE.BIN", "System Volume Information"}
    exclude_folder_seen_log = {}  # type: typing.Dict[str, typing.List[str]]
    files = []
    size = 0
    for path in sorted(paths):
        for root, dirs, filenames in os.walk(path, onerror=walk_error):
            if ignore_dotfiles:
                filenames = [f for f in filenames if not f[0] == "."]
                dirs[:] = [d for d in dirs if not d[0] == "."]
            if ignore_windows_volume_folders:
                for directory in [d for d in dirs if d in EXCLUDE_FOLDERS]:
                    if directory not in exclude_folder_seen_log:
                        exclude_folder_seen_log[directory] = []
                        exclude_folder_seen_log[directory].append(os.path.join(root, directory))
                        log.info(
                            "'%s' will not be processed (Windows system directory)",
                            os.path.join(root, directory),
                        )
                    else:
                        exclude_folder_seen_log[directory].append(os.path.join(root, directory))
                        log.warning(
                            "Excluded folder '%s' has been excluded more than once within path '%s'"
                            " - this is unexpected, as this folder should only be found in the root"
                            " of a drive. Be advised that the following folders will NOT be"
                            " processed: %s",
                            directory,
                            path,
                            get_list_as_str(exclude_folder_seen_log[directory]),
                        )
                dirs[:] = [d for d in dirs if not d in EXCLUDE_FOLDERS]
            for name in filenames:
                try:
                    size += os.path.getsize(os.path.join(root, name))
                    files.append(os.path.join(root, name))
                except (FileNotFoundError, PermissionError):
                    log.warning(
                        "File '%s' cannot be accessed and will not be processed - try running as"
                        " admin",
                        os.path.join(root, name),
                    )
    return sorted(files), size


def get_list_as_str(list_to_convert: typing.List[str]) -> str:
    """Convert list into comma separated string, with each element enclosed in single quotes"""
    return ", ".join(["'{}'".format(list_item) for list_item in list_to_convert])


def diagnose_null_bytes(bzdata_folder_path: typing.Optional[str]) -> typing.Optional[bool]:
    """Check if files in source path(s) are found as records in Backblaze log data"""
    log = logging.getLogger(__name__)
    # Check passed arguments and return if issues
    platform_system = platform.system()
    # Confirm bzdata folder location
    if bzdata_folder_path is not None:
        if not os.path.isdir(bzdata_folder_path):
            log.error("Backblaze folder path '%s' not found", bzdata_folder_path)
            return None
        if not os.path.isfile(os.path.join(bzdata_folder_path, "bzexcluderules_mandatory.xml")):
            log.error(
                "Backblaze folder path '%s' does not appear to contain expected configuration data"
                " - has the correct path been provided?",
                bzdata_folder_path,
            )
            return None
    else:
        if platform_system == "Windows":
            bzdata_folder_path = r"C:\ProgramData\Backblaze\bzdata"
        elif platform_system == "Darwin":
            bzdata_folder_path = "/Library/Backblaze.bzpkg/bzdata"
        else:
            log.error(
                "Unrecognised operating system ('%s') in use - cannot predict 'bzdata' folder"
                " location",
                platform.system(),
            )
            return None
    # Print intentions to user
    log.info(
        "Diagnosis of null bytes will be performed against Backblaze log data in '%s'",
        bzdata_folder_path,
    )

    # Parse data in bzdone files
    bzdatacenter_folder_path = os.path.join(bzdata_folder_path, "bzbackup", "bzdatacenter")
    bzdone_file_paths, _ = get_file_paths_and_total_size([bzdatacenter_folder_path], True, True)
    bzdone_file_paths = [
        path
        for path in bzdone_file_paths
        if os.path.basename(path).startswith("bz_done_")
        and os.path.splitext(path)[1].lower() == ".dat"
    ]
    if not bzdone_file_paths:
        log.error("No bz_done dat files found at path '%s'", bzdatacenter_folder_path)
        return None

    bz_done_line_counts = {}  # type: typing.Dict[str, int]
    null_rows = {}  # type: typing.Dict[str, typing.List[NullRow]]
    for bzdone_file_path in bzdone_file_paths:
        total_row_count = 0
        with open(bzdone_file_path, "r", encoding="utf-8", errors="ignore") as file_handler:
            for row in file_handler:
                total_row_count += 1
                if "\0" in row:
                    null_row = NullRow(
                        content=row,
                        length=len(row),
                        row_position=total_row_count,
                        null_count=row.count("\0"),
                        null_locations=[i for i, x in enumerate(row) if x == "\0"],
                    )
                    if bzdone_file_path not in null_rows:
                        null_rows[bzdone_file_path] = []
                    null_rows[bzdone_file_path].append(null_row)
        bz_done_line_counts[bzdone_file_path] = total_row_count

    log.info("%s of %s bz_done files have null bytes", len(null_rows), len(bzdone_file_paths))
    for bzdone_file_path, row_list in null_rows.items():
        log.info(
            "%s of %s rows in '%s' have null chars, as follows:",
            len(row_list),
            bz_done_line_counts[bzdone_file_path],
            bzdone_file_path,
        )
        for null_row in row_list:
            log.debug(null_row.content.replace("\0", "[NUL]"))
            log.info(
                "Row position: %s | Row length: %s | Total null chars: %s | Null char"
                " locations: %s",
                null_row.row_position,
                null_row.length,
                null_row.null_count,
                null_row.null_locations,
            )

    return True


def main() -> None:
    """Captures args via argparse and forwards to core logic in diagnose_null_bytes"""
    run_time = datetime.datetime.now()
    datetime_string = run_time.strftime("%Y%m%d_%H%M%S")

    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-l",
        "--log",
        action="store_true",
        help=(
            "Write log files (will be written to folder 'bbcheck_logs' if alternate path not"
            " specified with --logfolder)"
        ),
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Show debug log entries in console and write to separate log file in log folder",
    )
    parser.add_argument(
        "--logfolder",
        default="bbcheck_logs",
        help=(
            "Folder to write logs to (if not specified, folder 'bbcheck_logs' will be used in"
            " current working folder)"
        ),
    )
    parser.add_argument(
        "-b",
        "--bzdata-folder",
        type=str,
        help=(
            "Path to Backblaze 'bzdata' folder (if not specified, defaults for Windows and Mac will"
            " be used)"
        ),
    )

    args = parser.parse_args()

    # Set up logging
    if args.log or args.debug:
        pathlib.Path(args.logfolder).mkdir(parents=True, exist_ok=True)
    log, counter_handler = _prepare_logging(
        datetime_string=datetime_string,
        write_logs=args.log,
        folder_path=args.logfolder,
        identifier="bbcheck",
        args=dict(vars(args)),
        show_debug=args.debug,
        write_debug=args.debug,
    )
    if args.log or args.debug:
        log.info("Logs will be stored in folder '%s'", args.logfolder)

    # Run core logic
    diagnose_null_bytes(bzdata_folder_path=args.bzdata_folder)

    # Mention any errors and close out
    if counter_handler.count["WARNING"] > 0 or counter_handler.count["ERROR"] > 0:
        log.warning(
            "Script complete; %s warnings/errors occurred requiring review (see log entries"
            " above%s)",
            counter_handler.count["WARNING"] + counter_handler.count["ERROR"],
            ", replicated in folder '{}'".format(args.logfolder) if args.log or args.debug else "",
        )
    else:
        log.info("Script complete; no errors reported")


if __name__ == "__main__":
    # Entry point when running script directly
    main()
