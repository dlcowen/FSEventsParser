Overview

Parse FSEvent records from allocated and carved GZIP files. Outputs parsed information to a tab delimited txt file and a SQLite database. 

The script will check to see if each file is a valid GZIP file. If it is, the script will search within the uncompressed GZIP file for an 1SLD header signature. If present, records will be parsed from the FSEvents file.

Errors and exceptions are recorded in the exceptions logfile.

Command Syntax: > python 'FSEParser.py' 'path_to_fsevents'

Output files (located in the directory of the python script after parsing has completed):
-	fsevents.sqlite: SQLite database containing records parsed from FSEvent files.
-	FSEvents-Parsed_Records-tab_delimited.txt: Tab delimited text file containing records parsed from FSEvent files.
-	FSEvents-EXCEPTIONS_LOG.txt: Log file containing information related to parsing errors.

Notes

Parsed records can be in excess of 1 million records.

Place all FSEvent files and carved GZIP files in the same directory. Then run the script and point it at that directory. The script will not search subdirectories.
Currently the script does not perform deduplication. When carving for GZIP files, if you carve from allocated, you will experience duplicated records

Column Reference

record_filename: The path and filename stored in the current record.
record_mask: The record's parsed mask. This is what happened to the file. Possible values include: MustScanSubDirs, UserDropped, KernelDropped, EventIdsWrapped, HistoryDone, RootChanged, Mount, Unmount, UseCFTypes, NoDefer, WatchRoot, IgnoreSelf, ItemIsFile, ItemIsDir, ItemIsSymlink, ItemCreated, ItemRemoved, ItemInodeMetaMod, ItemRenamed, ItemModified, ItemFinderInfoMod, ItemChangeOwner, ItemXattrMod.
record_mask_hex: The hex representation of the record's mask.
asl_name_date_stripped: The date(s) that were stripped from the name of an Apple System Log file that was modified/created within an FSEvents file. This value is assigned to all records parsed from a FSEvents file and represents the approximate date that the event took place. If no ASL file was found matching the modified/created criteria, this field will be "UNKNOWN".
record_wd: The event ID for the current record that was parsed. The event ID (WD) is assigned to a file in chronological order, as the event occurred.
record_number_parse_order: The record number as it was parsed from the FSEvents file occurring in sequential order within the current FSEvents file, beginning to end. This number was generated by the script.
record_length: The length of the current record including the fullpath and the raw record.
max_wd_record_number: The value that was parsed from the FSEvents filename, allocated only. If the FSEvents file was from unallocated space, this value will be 0 or unknown.
record_end_relative_offset: The end offset of the current record within the FSEvents file.
current_page_size: The size in bytes of the current page within the FSEvents file. There can be multiple pages within an FSEvents file.
source_fsevents_filesize: The uncompressed size of the current FSEvents file that was identified  by the script.
source_fsevents_file: The name of the FSEvents file that the current record was parsed from.
source_fsevents_path: The path of the FSEvents file that the current record was parsed from.
file_header-unknown_hex: The hex representation of the unknown value in the current page header.
file_header-unknown_int: The integer representation of the unknown value in the current page header.

