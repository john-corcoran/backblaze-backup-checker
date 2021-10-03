# Backblaze Backup Checker

This Python script compares metadata captured from files within source folders against data parsed from Backblaze Cloud Backup's log files (`bz_done` files, stored locally), reporting any files that do not appear to have been uploaded or that have conflicting cryptographic hash values, as well as files that would not be uploaded due to filter/exclusion rules.

The primary use case is to provide confidence that files have been backed up with expected integrity, or if not, what filter/exclusion rules may be blocking the backup.

**Due to limited availability of test data, this script is currently in alpha state. It is likely that false positives will be reported (see Known Issues below).**

## Prerequisites

Python 3.7 or later is required, with the `tqdm` progress bar module installed (`pip install tqdm`).

This script has been tested using Backblaze client version 7.0.2.470 on macOS 11.5, and client version 8.0.0.517 on Windows 10 20H2.

This script is only compatible with 'Version 5' log records (the standard used by Backblaze clients since October 2014). Any log records that are in an older format will not be processed.

## Script behaviour

Backblaze configuration and log data, as well as files in source folders, are opened in read-only mode and will not be modified.

For each source folder specified by the user, file path and size metadata will be only captured for those files that 'pass' the filter/exclusion rules and have not been created or modified in the last 24 hours (to allow the Backblaze client time to upload them). Filter/exclusion rules will be read automatically from Backblaze configuration data; both Backblaze-default and user-configured rules will be processed.

Under default script configuration, SHA1 hash metadata will also be generated for files that are <= 100MB in size, in order to confirm file integrity. (Files > 100MB in size are split in the Backblaze logs; the original hash value is not retained, and I am unaware of any technique to construct the true SHA1 hash from the available split data.)

Symlinks will be ignored during processing as these are not backed up by Backblaze. Mac hidden files `.DS_Store` and `.localized` will also be ignored.

Progress is reported within the console (and if specified, to log files). At script conclusion, up to four text files will be created in either the current working folder or a user-specified output folder, with filenames and comma-separated contents as follows:

1. `[datetime]_backblaze_uploaded_files.txt`: list of files that are present and correct in Backblaze log data, indicating successful upload.
2. `[datetime]_backblaze_mismatch_files.txt`: list of files whose path is either not present in Backblaze log data, or the path is present but SHA1/size metadata does not match between the local file and Backblaze log data. Files listed in this output may not have been uploaded to Backblaze successfully - but be aware that there are likely to be false positives (see Known Issues below).
3. `[datetime]_backblaze_excluded_by_filter_files.txt`: list of files that have not been uploaded to Backblaze due to filter/exclusion rules, with details of which rules the files are 'failing' on.
4. `[datetime]_backblaze_recent_files_not_processed.txt`: list of files created or modified in the last 24 hours are listed in this output and not processed during script execution (as Backblaze may not have had time to upload them yet).

## Recommended usage

It is recommended that:

1. Specific folders containing user data are processed rather than full operating system drives. This is because various permissions errors and temporary files will be encountered if an entire operating system drive is processed, which will complicate the output (although the script should still run).
2. The script is run only after sufficient time has been allowed for files to have been uploaded to Backblaze. Files created or updated within the last 24 hours will be identified and not processed, but this approach is not robust (further script development to account for data within `bz_todo` log files would enable accurate filtering of files that are still being uploaded).

## Script usage

Syntax:

    python3 bbcheck.py source_path [source_path ...] [flags]

Usage example (Windows) with two source folders:

    python3 bbcheck.py C:\Users\john\Documents "E:\data folder"

Usage example (Mac) with one source folder:

    python3 bbcheck.py /Users/john/Documents

Absolute or relative paths may be provided; all metadata generated will revert to absolute paths.

Flags can be viewed using: `python3 bbcheck.py --help`, and are as follows:

- `-l` or `--log`: opt to write the status messages displayed in the console to a log file in the log folder.
- `-d` or `--debug`: display debug messages and write these to a dedicated debug log file in the log folder.
- `--logfolder [str]`: folder to write logs to (if not specified, the default of `bbcheck_logs` will be used).
- `-o [str]` or `--output [str]`: folder to write check results to (if not specified, results will be written to the current working folder).
- `-b [str]` or `--bzdata-folder [str]`: by default, the script will attempt to read Backblaze configuration and log data from standard client install locations for Windows and Mac. An alternative path to the `bzdata` folder may be provided with this flag.
- `-s` or `--only-check-size`: by default, SHA1 hash values will be generated for the integrity check for files <= 100MB in size. Hash data may take a long time to generate for large source folders; this flag sets the script to instead check integrity using file size metadata, which should execute quickly (but is not a true integrity check and is therefore less reliable).
- `--hash-files [str ... str]`: instead of generating SHA1 hash data during script execution, hash file(s) created using the `hash` mode in [Vericopy](https://github.com/john-corcoran/vericopy) may be used as a lookup. This approach allows for quick successive executions of this script, and is reliable on condition that files within the source folders are not changed between script executions.

Usage example (Windows) incorporating flags:

    python3 bbcheck.py C:\Users\john\Documents "E:\data folder" -l -o output_folder -s --hash-files e_drive_hashes.txt -b "C:\ProgramData\Backblaze Alternative Location\bzdata"

## Known issues

1. Hash/size mismatches may be reported for some files, where Backblaze logs reference an incorrect hash/size value for a file - but upon recovery of the file using the Backblaze web interface, the correct original file (with correct hash/size) will be downloaded. In testing this behaviour seems prevalent for certain file types, such as `.doc` files, but as yet I have not discovered the reason for this behaviour.
2. Although symlinks are not processed during script execution, Mac alias links will be processed and raised (incorrectly) as missing files.
3. Depending on upload speed and duration the client has been running since files are created or modified, it is possible that files may be reported as missing that are still uploading (further script development to account for data within `bz_todo` log files would mitigate this).

## Privacy, log data, and uninstallation

This script runs entirely locally; neither Backblaze nor any other third party services are communicated with.

Script output is stored by default in the folder the script is executed in. If `-l` or `-d` is used to output logs to a file, these are stored by default in folder `bbcheck_logs` (created in the folder that the script is executed in). Debug logs may contain sensitive information, such as system details (including Python version and operating system), command line arguments used, and events occurring with data processed during script execution.

Full uninstallation can be achieved by:

1. Deleting the script and any other downloaded files (e.g. the readme and license).
2. Deleting script output and the logs folder (`bbcheck_logs` by default).
3. If desired, removing the `tqdm` library and Python runtime.

## Contributing

If you would like to contribute, please fork the repository and use a feature branch. Pull requests are warmly welcome.

## Licensing

The code in this project is licensed under the MIT License.
