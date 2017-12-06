Overview
---------------------

FSEvents files are written to disk by macOS APIs and contain historical records of file system activity that occurred for a particular volume. They can be found on devices running macOS and devices that were plugged in to a device running macOS.

FSEventsParser can be used to parse extracted FSEvents files from the '/.fseventsd/' folder and also from carved GZIP files. 

Create your own targeted reports by editing the 'report_queries.json' file or just get default targeted reports including:
- UserProfileActivity
- TrashActivity
- BrowserActivity
- DownloadsActivity
- MountActivity
- EmailAttachments
- UsersPictureTypeFiles
- UsersDocumentTypeFiles
- DropBoxActivity
- Box_comActivity


The parser outputs parsed information to tab delimited txt files and an SQLite database. Errors and exceptions are recorded in the exceptions logfile.

Usage
---------------------
    ==========================================================================
    FSEParser v 3.1  -- provided by G-C Partners, LLC
    ==========================================================================

    Usage: FSEParser_V3.1.py -c CASENAME -q REPORT_QUERY_FILE -s SOURCEDIR -o OUTDIR

    Options:
      -h, --help        show this help message and exit
      -c CASENAME       The name of the current session, used for naming standards
      -q REPORTQUERIES  The full path to the json file containing custom report
                        queries to generate targeted reports
      -s SOURCEDIR      The source directory containing fsevent files to be parsed
      -o OUTDIR         The destination directory used to store parsed reports

Notes
----------------------

- Parsed records can be in excess of 1 million records.
- The script does not recursively search subdirectories in the source_dir provided. All fsevent files including carved gzip if any must be place in the same directory.
- Currently the script does not perform deduplication. Duplicate records may occur when carved gzips are also parsed.


Ouput Column Reference
-----------------------

id: The fsevent record ID. Also refered to as the event record WD or Working Descriptor. The record ID is assigned in chronological order.

id_hex: The record ID in hex format

fullpath: The record fullpath.

filename: The record filename.

type: The file type of the record fullpath/the event type:
- FileEvent
- FolderEvent
- HardLink
- SymbolicLink

flags: The changes that occurred to the record fullpath:
- Created
- Modified
- Renamed
- Removed
- InodeMetaMod
- ExtendedAttrModified
- FolderCreated
- PermissionChange
- ExtendedAttrRemoved
- FinderInfoMod
- DocumentRevisioning
- Exchange
- ItemCloned        # High Sierra
- LastHardLinkRemoved
- Mount
- Unmount
- EndOfTransaction

approx_dates(plus_minus_one_day): Approximate dates (no times) that the event occurred. The date ranges were pulled using the name of Log files that have the Created flag within an FSEvents file. This value may or may not be off by one day due to timezone variances.

node_id: Introduced in HighSierra. The file system node ID (stored in the catalog file for HFS+) of the record fullpath at the time the event was recorded. This value is empty for MacOS versions prior to High Sierra.

record_end_offset: The end offset of the record within the decompressed fsevents file.

mask_hex: The hex representation of the record's mask.

source: The fullpath of the FSEvents file that the record was parsed from.

source_modified_time: The FSEvents source file modified date.