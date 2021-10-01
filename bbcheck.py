#!/usr/bin/env python3

"""Check Backblaze logs against files in source folders to confirm data has been backed up OK"""

import argparse
import csv
import dataclasses
import datetime
import hashlib
import logging
import operator
import os
import pathlib
import platform
import typing
import xml.etree.ElementTree

import tqdm


@dataclasses.dataclass
class BzdoneMetadata:
    """Dataclass for each file record parsed from bz_done log files"""

    date_time: str  # datetime format is YYYYMMDDHHMMSS so sorts OK without needing datetime convert
    instruction: str
    sha1_value: str
    size: int


@dataclasses.dataclass
class ExcludeRule:
    """Dataclass for each exclude rule"""

    platform: typing.Optional[str] = None
    os_version: typing.Optional[str] = None
    path: typing.Optional[str] = None
    contains_1: typing.Optional[str] = None
    contains_2: typing.Optional[str] = None
    does_not_contain: typing.Optional[str] = None
    ends_with: typing.Optional[str] = None
    has_file_extension: typing.Optional[str] = None


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


def get_list_as_str(list_to_convert: typing.List[str]) -> str:
    """Convert list into comma separated string, with each element enclosed in single quotes"""
    return ", ".join(["'{}'".format(list_item) for list_item in list_to_convert])


def get_missing_sources(
    source_paths: typing.List[str], files_only: bool = False
) -> typing.List[str]:
    """Return list of any source paths that aren't a file or a folder"""
    missing_sources = [
        source_path
        for source_path in source_paths
        if (not os.path.isdir(source_path) or files_only) and not os.path.isfile(source_path)
    ]
    return missing_sources


def bytes_filesize_to_readable_str(bytes_filesize: int) -> str:
    """Convert bytes integer to kilobyte/megabyte/gigabyte/terabyte equivalent string"""
    if bytes_filesize < 1024:
        return "{} B"
    num = float(bytes_filesize)
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(num) < 1024.0:
            return "{:.1f} {}".format(num, unit)
        num /= 1024.0
    return "{:.1f} {}".format(num, "TB")


def hash_file_at_path(filepath: str, algorithm: str) -> str:
    """Return str containing lowercase hash value of file at a file path"""
    block_size = 64 * 1024
    hasher = getattr(hashlib, algorithm)()
    with open(filepath, "rb") as file_handler:
        while True:
            data = file_handler.read(block_size)
            if not data:
                break
            hasher.update(data)
    return hasher.hexdigest()


def compare_hashes_for_a_file(hash_set_1: typing.List[str], hash_set_2: typing.List[str]) -> bool:
    """Get a common hash between two sets of hashes, and compare if they match"""
    # Reverse sort on value length gives longest and therefore 'best' hash as first list item
    hash_set_1.sort(key=len, reverse=True)
    hash_set_2.sort(key=len, reverse=True)
    hash_set_1_preferred_hash = hash_set_1.pop(0)
    hash_set_2_preferred_hash = hash_set_2.pop(0)
    # Whittle away the preferred hashes until we have a set that match and therefore can be compared
    while len(hash_set_1_preferred_hash) != len(hash_set_2_preferred_hash):
        try:
            if len(hash_set_1_preferred_hash) < len(hash_set_2_preferred_hash):
                hash_set_2_preferred_hash = hash_set_2.pop(0)
            else:
                hash_set_1_preferred_hash = hash_set_1.pop(0)
        except IndexError:  # Will occur if we don't have a common hash type, so can't verify
            return False
    if hash_set_1_preferred_hash == hash_set_2_preferred_hash:
        return True
    return False


def get_dict_from_hash_files(
    hash_file_paths: typing.List[str],
    only_check_size_flag: bool,
) -> typing.Dict[str, typing.Dict[str, typing.Any]]:
    """Turn contents of hash file at path into metadata dict object"""
    log = logging.getLogger(__name__)
    results = {}  # type: typing.Dict[str, typing.Dict[str, typing.Any]]
    for hash_file_path in hash_file_paths:
        with open(hash_file_path, "r", encoding="utf-8", errors="ignore") as file_handler:
            line_count = 0
            for line in file_handler:
                line_data = line.strip().split("|")
                try:
                    hash_values = [hash for hash in line_data[0:3] if hash != ""]
                    path = "|".join(line_data[3:-3])  # This should allow filenames containing pipes
                    size = line_data[-3]
                    ctime = line_data[-2]
                    mtime = line_data[-1]
                except IndexError:
                    log.error("Hash file '%s' does not match expected file format", hash_file_path)
                    return {}
                if path not in results:
                    results[path] = {}
                    results[path]["size"] = int(size)
                    results[path]["ctime"] = float(ctime)
                    results[path]["mtime"] = float(mtime)
                    results[path]["hashes"] = ["", "", ""]
                    for hash_value in hash_values:
                        results[path]["hashes"].append(hash_value)
                        if len(hash_value) == 64:
                            results[path]["sha256"] = hash_value
                            results[path]["hashes"][0] = hash_value
                        elif len(hash_value) == 40:
                            results[path]["sha1"] = hash_value
                            results[path]["hashes"][1] = hash_value
                        elif len(hash_value) == 32:
                            results[path]["md5"] = hash_value
                            results[path]["hashes"][2] = hash_value
                    if not only_check_size_flag and "sha1" not in results[path]:
                        log.error(
                            "SHA1 hash not found for file '%s' in hash file '%s' - please re-hash"
                            " using SHA1",
                            path,
                            hash_file_path,
                        )
                else:
                    # Alarm if the metadata has changed
                    if not compare_hashes_for_a_file(
                        results[path]["hashes"], hash_values
                    ) or results[path]["size"] != int(size):
                        log.error(
                            "While building pre computed hash dictionary, file path '%s' was"
                            " identified multiple times with different metadata across hash"
                            " files - hash files therefore cannot be used as verification"
                            " results would be inaccurate",
                            path,
                        )
                        return {}
                line_count += 1
        if line_count == 0:
            log.error("'%s' is empty", hash_file_path)
            return {}
    return results


def filter_paths_using_excludes(
    root: str, filenames: typing.List[str], exclude_rules: typing.List[ExcludeRule]
) -> typing.Tuple[typing.List[str], typing.List[str]]:
    """Return lists of files that pass and fail Backblaze filter rules"""
    log = logging.getLogger(__name__)
    path_parts = pathlib.Path(root).parts[1:]
    dir_path = str(pathlib.Path(*path_parts)).lower()
    if platform.system() == "Windows":
        other_platform_shortname = "mac"
        os_vers = platform.release().lower()
        dir_path += "\\"
    elif platform.system() == "Darwin":
        other_platform_shortname = "win"
        os_vers, _, _ = platform.mac_ver()
        dir_path += "/"
    else:
        log.error(
            "Unrecognised operating system ('%s') in use - cannot filter exclude rules",
            platform.system(),
        )
        return [], []
    filenames_to_remove = set()
    rule_hits_per_file = {}  # type: typing.Dict[str, typing.List[str]]
    all_full_filepaths = [os.path.join(root, filename) for filename in filenames]
    files_failing_filter = []
    for rule in exclude_rules:
        rule_hits = {}  # type: typing.Dict[str, typing.List[bool]]
        # If the rule applies to another OS, skip immediately
        if rule.platform == other_platform_shortname:
            continue
        # If the rule applies to another OS version, skip immediately
        if rule.os_version is not None and rule.os_version != os_vers:
            continue
        # If the dir path doesn't match, skip immediately
        if rule.path is not None and not dir_path.startswith(rule.path):
            continue
        # If none of the files contain the 'contain_1' value, skip immediately
        if rule.contains_1 is not None and not any(
            rule.contains_1 in path.lower() for path in all_full_filepaths
        ):
            continue
        # otherwise in our rule_hits, track which files have a hit
        else:
            if rule.contains_1 is not None:
                for full_path in all_full_filepaths:
                    if full_path not in rule_hits:
                        rule_hits[full_path] = []
                    if rule.contains_1 in full_path.lower():
                        rule_hits[full_path].append(True)
                    else:
                        rule_hits[full_path].append(False)
        # If none of the files contain the 'contain_2' value, skip immediately
        if rule.contains_2 is not None and not any(
            rule.contains_2 in path.lower() for path in all_full_filepaths
        ):
            continue
        # otherwise in our rule_hits, track which files have a hit
        else:
            if rule.contains_2 is not None:
                for full_path in all_full_filepaths:
                    if full_path not in rule_hits:
                        rule_hits[full_path] = []
                    if rule.contains_2 in full_path.lower():
                        rule_hits[full_path].append(True)
                    else:
                        rule_hits[full_path].append(False)
        # If none of the files do not contain the 'does_not_contain' value, skip immediately
        if rule.does_not_contain is not None and not any(
            rule.does_not_contain not in path.lower() for path in all_full_filepaths
        ):
            continue
        # otherwise in our rule_hits, track which files have a hit
        else:
            if rule.does_not_contain is not None:
                for full_path in all_full_filepaths:
                    if full_path not in rule_hits:
                        rule_hits[full_path] = []
                    if rule.does_not_contain not in full_path.lower():
                        rule_hits[full_path].append(True)
                    else:
                        rule_hits[full_path].append(False)
        # If none of the files end with the 'ends_with' value, skip immediately
        if rule.ends_with is not None and not any(
            path.lower().endswith(rule.ends_with) for path in all_full_filepaths
        ):
            continue
        # otherwise in our rule_hits, track which files have a hit
        else:
            if rule.ends_with is not None:
                for full_path in all_full_filepaths:
                    if full_path not in rule_hits:
                        rule_hits[full_path] = []
                    if full_path.lower().endswith(rule.ends_with):
                        rule_hits[full_path].append(True)
                    else:
                        rule_hits[full_path].append(False)
        # If none of the files have the 'has_file_extension' extension, skip immediately
        if rule.has_file_extension is not None and not any(
            os.path.splitext(path)[1][1:].lower() == rule.has_file_extension
            for path in all_full_filepaths
        ):
            continue
        # otherwise in our rule_hits, track which files have a hit
        else:
            if rule.has_file_extension is not None:
                for full_path in all_full_filepaths:
                    if full_path not in rule_hits:
                        rule_hits[full_path] = []
                    if os.path.splitext(full_path)[1][1:].lower() == rule.has_file_extension:
                        rule_hits[full_path].append(True)
                    else:
                        rule_hits[full_path].append(False)
        # If we've got this far without continue hitting, and there's no individual rule hits, it
        # means that all files should be filtered out
        if not rule_hits:
            filenames_to_remove.update([x for x in filenames])
            for full_path in all_full_filepaths:
                if full_path not in rule_hits_per_file:
                    rule_hits_per_file[full_path] = []
                rule_hits_per_file[full_path].append(str(rule))
        # otherwise, we only want to filter out files with rule_hits where every rule_hit for the
        # file is true
        else:
            for full_path, hits in rule_hits.items():
                if all(hits):
                    filenames_to_remove.add(os.path.basename(full_path))
                    if full_path not in rule_hits_per_file:
                        rule_hits_per_file[full_path] = []
                    rule_hits_per_file[full_path].append(str(rule))

    # Remove any symlinks
    for full_path in all_full_filepaths:
        if os.path.islink(full_path):
            filenames_to_remove.add(os.path.basename(full_path))
            if full_path not in rule_hits_per_file:
                rule_hits_per_file[full_path] = []
            rule_hits_per_file[full_path].append("Symlink")

    # Final return list creation
    if filenames_to_remove:
        for full_path in [os.path.join(root, x) for x in filenames_to_remove]:
            files_failing_filter.append(
                "{},{}".format(full_path, str(rule_hits_per_file[full_path]))
            )
    files_passing_filter = [x for x in filenames if x not in filenames_to_remove]
    return files_passing_filter, files_failing_filter


def get_file_paths_and_total_size(
    paths: typing.List[str],
    ignore_dotfiles: bool,
    ignore_windows_volume_folders: bool,
    log: typing.Optional[logging.Logger] = None,
    exclude_rules: typing.Optional[typing.List[ExcludeRule]] = None,
) -> typing.Tuple[typing.List[str], int, typing.List[str]]:
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
    files_failing_filter = []
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
            if exclude_rules is not None:
                filenames, files_failing_filter_update = filter_paths_using_excludes(
                    root, filenames, exclude_rules
                )
                files_failing_filter.extend(files_failing_filter_update)
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
    return sorted(files), size, files_failing_filter


def parse_bz_done_files(
    bzdone_file_paths: typing.List[str], size_flag: bool = False
) -> typing.Optional[typing.Dict[str, typing.Union[str, int]]]:
    """Parse 'bz_done' log files and return dictionary of metadata per file"""
    # Check passed arguments and return if issues
    log = logging.getLogger(__name__)
    EXIST_FLAGS = {"+", "=", "!"}
    if not bzdone_file_paths:
        log.error("Bzdone file paths list is empty")
        return None

    # Parse files
    bz_metadata = {}  # type: typing.Dict[str, typing.List[BzdoneMetadata]]
    for bzdone_file_path in bzdone_file_paths:
        with open(bzdone_file_path, "r", encoding="utf-8", errors="ignore") as file_handler:
            reader = csv.reader(file_handler, delimiter="\t")
            for row in reader:
                try:
                    file_path = row[13]
                    date_time = row[3]
                    instruction = row[1]
                    sha1_value = row[8]
                    size = int(row[12])
                    if file_path not in bz_metadata:
                        bz_metadata[file_path] = []
                    bz_metadata[file_path].append(
                        BzdoneMetadata(date_time, instruction, sha1_value, size)
                    )
                except IndexError:
                    log.warning("IndexError in file '%s', row data: '%s'", bzdone_file_path, row)

    results = {}  # type: typing.Dict[str, typing.Union[str, int]]
    # For every file path recorded in Backblaze logs, sort to get the most recent entries, and
    # whittle until we see the most recent is either a 'file create' or a 'file delete' event
    for file_path in sorted(bz_metadata):
        for metadata in sorted(
            bz_metadata[file_path], key=operator.attrgetter("date_time"), reverse=True
        ):
            # In testing, flags '!' and 'x' (particularly 'x') aren't useful for filtering -
            # for example, a file can be de-duped, which creates a second entry for the file in the
            # logs with a '=' event - the 'original', 'duped' file will be expunged with an 'x'
            # even though the file itself hasn't been deleted. Basically these two flags aren't
            # useful for our filtering purpose here
            if metadata.instruction == "!" or metadata.instruction == "x":
                continue
            # If it's not a create event, then the file has been deleted, so don't check further
            if metadata.instruction not in EXIST_FLAGS:
                break
            # If the file has '!' then it's been split in the logs (i.e. > 100MB), so we can't
            # use the hash value - so set placeholder '-'
            if "!" in [metadata.instruction for metadata in bz_metadata[file_path]]:
                results[file_path] = "-"
            else:
                if not size_flag:
                    results[file_path] = metadata.sha1_value
                else:
                    results[file_path] = metadata.size
            break

    return results


def get_excludes(bzdata_folder_path: str) -> typing.Optional[typing.List[ExcludeRule]]:
    """Read exclude rules from Backblaze config files and return list of ExcludeRule dataclasses"""
    log = logging.getLogger(__name__)
    # Check passed arguments and return if issues
    if not os.path.isdir(bzdata_folder_path):
        log.error("Backblaze folder path '%s' not found", bzdata_folder_path)
        return None
    if not os.path.isfile(os.path.join(bzdata_folder_path, "bzexcluderules_mandatory.xml")):
        log.error(
            "Backblaze folder path '%s' does not appear to contain expected configuration data -"
            " has the correct path been provided?",
            bzdata_folder_path,
        )
        return None

    # 1. Get bzexcluderules_mandatory.xml and bzexcluderules_editable.xml excludes
    exclude_file_paths = [
        os.path.join(bzdata_folder_path, "bzexcluderules_mandatory.xml"),
        os.path.join(bzdata_folder_path, "bzexcluderules_editable.xml"),
    ]
    if get_missing_sources(exclude_file_paths):
        log.error(
            "Item(s) %s not found",
            get_list_as_str(get_missing_sources(exclude_file_paths)),
        )
        return None
    excludes = []
    for exclude_file_path in exclude_file_paths:
        root = xml.etree.ElementTree.parse(exclude_file_path).getroot()
        for item in root:
            plat = item.attrib["plat"]
            os_version = None if item.attrib["osVers"] == "*" else item.attrib["osVers"]
            # Windows 'skipfirstchar' rules are formatted differently - unify by taking from [2:]
            if plat == "win":
                path = (
                    None
                    if item.attrib["skipFirstCharThenStartsWith"] == "*"
                    else item.attrib["skipFirstCharThenStartsWith"][2:].lower()
                )
            else:
                path = (
                    None
                    if item.attrib["skipFirstCharThenStartsWith"] == "*"
                    else item.attrib["skipFirstCharThenStartsWith"].lower()
                )
            contains_1 = (
                None if item.attrib["contains_1"] == "*" else item.attrib["contains_1"].lower()
            )
            contains_2 = (
                None if item.attrib["contains_2"] == "*" else item.attrib["contains_2"].lower()
            )
            does_not_contain = (
                None
                if item.attrib["doesNotContain"] == "*"
                else item.attrib["doesNotContain"].lower()
            )
            ends_with = None if item.attrib["endsWith"] == "*" else item.attrib["endsWith"].lower()
            has_file_extension = (
                None
                if item.attrib["hasFileExtension"] == "*"
                else item.attrib["hasFileExtension"].lower()
            )
            excludes.append(
                ExcludeRule(
                    plat,
                    os_version,
                    path,
                    contains_1,
                    contains_2,
                    does_not_contain,
                    ends_with,
                    has_file_extension,
                )
            )

    # 2. Get bzinfo.xml excludes
    bzinfo_path = os.path.join(bzdata_folder_path, "bzinfo.xml")
    if not os.path.isfile(bzinfo_path):
        log.error("bzinfo.xml file not found in expected location '%s'", bzinfo_path)
        return None
    root = xml.etree.ElementTree.parse(bzinfo_path).getroot()
    excludes_tag = root.findall("globalexcludes")
    if len(excludes_tag) != 1:
        log.warning(
            "Unexpected number of excludes tags in bzinfo.xml file, filtering may be inaccurate"
        )
    file_ext_excludes = excludes_tag[0].attrib["excludefiletypes"]
    for file_ext in file_ext_excludes.split(","):
        excludes.append(ExcludeRule(has_file_extension=file_ext))
    do_backup_tag = root.findall("do_backup")
    if len(do_backup_tag) != 1:
        log.warning(
            "Unexpected number of do_backup tags in bzinfo.xml file, filtering may be inaccurate"
        )
    for bzdirfilter in do_backup_tag[0]:
        if bzdirfilter.attrib["whichfiles"] == "none":
            path_parts = pathlib.Path(bzdirfilter.attrib["dir"]).parts[1:]
            dir_path = str(pathlib.Path(*path_parts)).lower()
            excludes.append(ExcludeRule(path=dir_path))

    # 3. manual rule for any .DS_Store and .localized files
    excludes.append(
        ExcludeRule(
            platform=None,
            os_version=None,
            path=None,
            contains_1=None,
            contains_2=None,
            does_not_contain=None,
            ends_with=".DS_Store".lower(),
            has_file_extension=None,
        )
    )
    excludes.append(
        ExcludeRule(
            platform=None,
            os_version=None,
            path=None,
            contains_1=None,
            contains_2=None,
            does_not_contain=None,
            ends_with=".localized".lower(),
            has_file_extension=None,
        )
    )

    return excludes


def check_backup(
    source_paths: typing.List[str],
    output_folder: typing.Optional[str],
    bzdata_folder_path: typing.Optional[str],
    only_check_size_flag: bool,
    hash_file_paths: typing.Optional[typing.List[str]],
    datetime_string: str,
) -> typing.Optional[bool]:
    """Check if files in source path(s) are found as records in Backblaze log data"""
    log = logging.getLogger(__name__)
    # Check passed arguments and return if issues
    if get_missing_sources(source_paths):
        log.error(
            "Item(s) %s not found",
            get_list_as_str(get_missing_sources(source_paths)),
        )
        return None
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
    if hash_file_paths is not None:
        if get_missing_sources(hash_file_paths):
            log.error(
                "Item(s) %s not found",
                get_list_as_str(get_missing_sources(hash_file_paths)),
            )
            return None
    # Convert paths to absolute equivalents
    source_paths = [os.path.abspath(path) for path in source_paths]
    # Print intentions to user
    log.info(
        "Source path(s) %s will be compared against Backblaze log data in '%s'",
        get_list_as_str(source_paths),
        bzdata_folder_path,
    )
    if output_folder is not None:
        pathlib.Path(output_folder).mkdir(parents=True, exist_ok=True)
        log.info("Findings will be written to output folder '%s'", output_folder)
    else:
        log.info("Findings will be written to current working folder")
    if only_check_size_flag:
        log.info("Only file size data (not SHA1 hash data) will be checked")
    pre_computed_hash_values = {}
    if hash_file_paths is not None:
        log.info(
            "Hash data will be ingested from hash file(s) %s", get_list_as_str(hash_file_paths)
        )
        pre_computed_hash_values = get_dict_from_hash_files(hash_file_paths, only_check_size_flag)

    # Get exclusion list from config files
    exclude_rules = get_excludes(bzdata_folder_path)
    if exclude_rules is None:
        log.error("Exclude rules could not be parsed")
        return None
    if platform_system != "Windows" and platform_system != "Darwin":
        log.error(
            "Unrecognised operating system ('%s') in use - cannot confirm exclude rules to use",
            platform_system,
        )
        return None

    # Parse data in bzdone files
    bzdatacenter_folder_path = os.path.join(bzdata_folder_path, "bzbackup", "bzdatacenter")
    bzdone_file_paths, _, _ = get_file_paths_and_total_size([bzdatacenter_folder_path], True, True)
    bzdone_file_paths = [
        path
        for path in bzdone_file_paths
        if os.path.basename(path).startswith("bz_done_")
        and os.path.splitext(path)[1].lower() == ".dat"
    ]
    if not bzdone_file_paths:
        log.error("No bz_done dat files found at path '%s'", bzdatacenter_folder_path)
        return None
    bzdone_metadata = parse_bz_done_files(bzdone_file_paths, only_check_size_flag)
    if not bzdone_metadata or bzdone_metadata is None:
        log.error("Error occurred while parsing bz_done metadata")
        return None

    # Hash live files in source path(s)
    live_files_metadata = {}
    file_paths_in_source = []
    source_size = 0
    files_failing_filter = []
    recent_files = []
    day_before = datetime.datetime.now() - datetime.timedelta(days=1)
    for source_path in source_paths:
        log.debug("Processing source path '%s'", source_path)
        if os.path.isdir(source_path):
            (
                file_paths_in_source_update,
                source_size_update,
                files_failing_filter_update,
            ) = get_file_paths_and_total_size(
                [source_path], False, False, exclude_rules=exclude_rules
            )
            file_paths_in_source.extend(file_paths_in_source_update)
            files_failing_filter.extend(files_failing_filter_update)
            source_size += source_size_update
        elif os.path.isfile(source_path):
            (
                filenames_passing_filter_update,
                files_failing_filter_update,
            ) = filter_paths_using_excludes(
                os.path.dirname(source_path), [os.path.basename(source_path)], exclude_rules
            )
            file_paths_in_source.extend(
                [
                    os.path.join(os.path.dirname(source_path), x)
                    for x in filenames_passing_filter_update
                ]
            )
            files_failing_filter.extend(
                [os.path.join(os.path.dirname(source_path), x) for x in files_failing_filter_update]
            )
            if filenames_passing_filter_update:
                source_size += os.path.getsize(source_path)
        else:
            log.warning("Non-file / non-folder '%s' has not been processed", source_path)

    # If we have files that don't pass the filter rules, inform user and write out details
    if files_failing_filter:
        output_filename = "{}_backblaze_excluded_by_filter_files.txt".format(datetime_string)
        if output_folder is not None:
            output_path = os.path.join(output_folder, output_filename)
        else:
            output_path = output_filename
        log.info(
            "%s files are excluded from Backblaze backup due to exclusion rules; details listed"
            " in output file '%s'",
            len(files_failing_filter),
            output_path,
        )
        with open(output_path, "w", encoding="utf-8", errors="ignore") as file_handler:
            file_handler.write("Path,Matching exclusion rule(s)\n")
            for excluded_file in files_failing_filter:
                file_handler.write("{}\n".format(excluded_file))

    log.info(
        "%s files%s in source folders that pass Backblaze exclude filters will be checked",
        len(file_paths_in_source),
        " ({}) ".format(bytes_filesize_to_readable_str(source_size))
        if file_paths_in_source
        else "",
    )
    # Process each file (get metadata and hash if <= 100MB)
    for file_path in tqdm.tqdm(file_paths_in_source):
        log.debug("Processing file '%s'", file_path)
        if not os.path.isfile(file_path):
            log.warning(
                "File '%s' was either deleted before it could be checked or is not a regular"
                " file (e.g. Unix pipe/socket) - will be skipped",
                file_path,
            )
            continue
        try:
            local_file_metadata = pathlib.Path(file_path).stat()
            ctime = datetime.datetime.fromtimestamp(local_file_metadata.st_ctime)
            mtime = datetime.datetime.fromtimestamp(local_file_metadata.st_mtime)
            if ctime > day_before or mtime > day_before:
                recent_files.append(file_path)
                continue
        except FileNotFoundError:
            log.warning("File '%s' was deleted before it could be checked", file_path)
            continue
        # lookup_value will be either the SHA1 hash or file size, depending on script config
        lookup_value = "-"  # type: typing.Union[str, int]
        try:
            file_size = os.path.getsize(file_path)
            if file_size <= 104857600:  # 100MB, at which point file will split
                try:
                    if file_path in pre_computed_hash_values:
                        if only_check_size_flag:
                            lookup_value = pre_computed_hash_values[file_path]["size"]
                        else:
                            lookup_value = pre_computed_hash_values[file_path]["sha1"]
                    else:
                        if only_check_size_flag:
                            lookup_value = file_size
                        else:
                            lookup_value = hash_file_at_path(file_path, "sha1")
                except PermissionError:
                    log.warning("PermissionError on: '%s' (try running script as admin)", file_path)
                    continue
                except OSError:
                    log.warning("OSError on: '%s' (file possibly deleted)", file_path)
                    continue
        except FileNotFoundError:
            log.warning("File '%s' was deleted before it could be checked", file_path)
            continue
        live_files_metadata[file_path] = lookup_value

    # If we have files created or modified in last 24 hours, inform user and write out details
    if recent_files:
        output_filename = "{}_backblaze_recent_files_not_processed.txt".format(datetime_string)
        if output_folder is not None:
            output_path = os.path.join(output_folder, output_filename)
        else:
            output_path = output_filename
        log.info(
            "%s files were identified created/updated in the last day, which have not been checked"
            " as Backblaze may not have processed them yet - details written to output file '%s'",
            len(recent_files),
            output_path,
        )
        with open(output_path, "w", encoding="utf-8", errors="ignore") as file_handler:
            file_handler.write("Recent file path\n")
            for recent_file in recent_files:
                file_handler.write("{}\n".format(recent_file))

    # Identify files in source folders that don't have paths or matching hashes in BB log data
    uploaded_file_list = []
    mismatch_files_list = []
    for path, lookup in live_files_metadata.items():
        if path not in bzdone_metadata:
            mismatch_files_list.append("{},{},missing path".format(path, lookup))
            continue
        elif lookup != "-" and bzdone_metadata[path] != "-":
            if only_check_size_flag:
                if int(bzdone_metadata[path]) != int(lookup):
                    mismatch_files_list.append(
                        "{},{},size mismatch (bz done size is {})".format(
                            path, lookup, bzdone_metadata[path]
                        )
                    )
                    continue
            else:
                if bzdone_metadata[path] != lookup:
                    mismatch_files_list.append(
                        "{},{},hash mismatch (bz done hash is {})".format(
                            path, lookup, bzdone_metadata[path]
                        )
                    )
                    continue
        uploaded_file_list.append("{},{}".format(path, lookup))

    # Inform user and write out details for 'successful' files (i.e. files with no discrepancies)
    if uploaded_file_list:
        output_filename = "{}_backblaze_uploaded_files.txt".format(datetime_string)
        if output_folder is not None:
            output_path = os.path.join(output_folder, output_filename)
        else:
            output_path = output_filename
        log.info(
            "%s files appear present and correct - details written to output file '%s'",
            len(uploaded_file_list),
            output_path,
        )
        with open(output_path, "w", encoding="utf-8", errors="ignore") as file_handler:
            if only_check_size_flag:
                file_handler.write("Path,Size\n")
            else:
                file_handler.write("Path,SHA1\n")
            for uploaded_file in uploaded_file_list:
                file_handler.write("{}\n".format(uploaded_file))

    # If we have files with discrepancies, inform user and write out details
    if mismatch_files_list:
        output_filename = "{}_backblaze_mismatch_files.txt".format(datetime_string)
        if output_folder is not None:
            output_path = os.path.join(output_folder, output_filename)
        else:
            output_path = output_filename
        log.info(
            "%s mismatches identified - details written to output file '%s'",
            len(mismatch_files_list),
            output_path,
        )
        with open(output_path, "w", encoding="utf-8", errors="ignore") as file_handler:
            file_handler.write("Path,SHA1,Is path missing or is there a hash mismatch?\n")
            for mismatch_file in mismatch_files_list:
                file_handler.write("{}\n".format(mismatch_file))

    return True


def main() -> None:
    """Captures args via argparse and [add functionality]"""
    run_time = datetime.datetime.now()
    datetime_string = run_time.strftime("%Y%m%d_%H%M%S")

    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "source_paths",
        type=str,
        nargs="+",
        help=(
            "One or more (space separated) paths to folder(s) containing data backed up via"
            " Backblaze"
        ),
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
        "-o",
        "--output",
        type=str,
        help=(
            "Folder to output results to (if not specified, results will be written to current"
            " working folder)"
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
    parser.add_argument(
        "-s",
        "--only-check-size",
        action="store_true",
        help=(
            "Only check file sizes of live files against Backblaze log data (rather than hash data)"
        ),
    )
    parser.add_argument(
        "--hash-files",
        type=str,
        nargs="+",
        help=(
            "Path to pre-computed hash data (generated using Vericopy -"
            " https://github.com/john-corcoran/vericopy) that can be used instead of calculating"
            " hash data during script execution"
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
    check_backup(
        source_paths=sorted(args.source_paths),
        output_folder=args.output,
        bzdata_folder_path=args.bzdata_folder,
        only_check_size_flag=args.only_check_size,
        hash_file_paths=args.hash_files,
        datetime_string=datetime_string,
    )

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
