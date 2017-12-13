Overview
---------------------

FSEvents files are written to disk by macOS APIs and contain historical records of file system activity that occurred for a particular volume. 
They can be found on devices running macOS and devices that were plugged in to a device running macOS. They are GZIP format, so you can also try carving for GZIPs to find FSEvents files that may be unallocated.

FSEventsParser can be used to parse FSEvents files from the '/.fseventsd/' on a live system or FSEvents files extracted from an image. 

Carved GZIP files from a macOS volume or a device that was plugged into a macOS system can also be parsed.

The parser outputs parsed information to tab delimited txt files and an SQLite database. Errors and exceptions are recorded in the exceptions logfile.

The report_queries.json file can be used to generate custom reports based off of SQLite queries. Use -q to specify the file's location when running the parser. 
You can download predefined SQLite queries from https://github.com/dlcowen/FSEventsParser/blob/master/report_queries.json.
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

Usage
---------------------
		==========================================================================
		FSEParser v 3.2 -- provided by G-C Partners, LLC
		==========================================================================
		Usage: FSEParser_V3.2.py -s SOURCEDIR -o OUTDIR [-c CASENAME -q REPORT_QUERIES]

		Options:
		  -h, --help         show this help message and exit
		  -s SOURCEDIR       REQUIRED. The source directory containing fsevent files
							 to be parsed
		  -o OUTDIR          REQUIRED. The destination directory used to store parsed
							 reports
		  -c CASENAME        OPTIONAL. The name of the current session, used for
							 naming standards. Defaults to 'Report'
		  -q REPORT_QUERIES  OPTIONAL. The location of the report_queries.json file
							 containing custom report queries to generate targeted
							 reports

Notes
----------------------

- Parsed records can be in excess of 1 million records.
- The script does not recursively search subdirectories in the source_dir provided. All FSEvents files including carved gzip if any must be placed in the same directory.
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
