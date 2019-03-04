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
- UsersPictureTypeFiles
- UsersDocumentTypeFiles
- DownloadsActivity
- TrashActivity
- BrowserActivity
- MountActivity
- EmailAttachments
- CloudStorageDropBoxActivity
- CloudStorageBoxActivity
- DSStoreActivity
- SavedApplicationState
- RootShellActivity
- GuestAccountActivity
- SudoUsageActivity
- BashActivity
- FailedPasswordActivity
- iCloudSyncronizationActivity
- SharedFileLists

Requires
---------------------
When the source type is an image DFVFS is required to run the script. Refer to https://github.com/log2timeline/dfvfs/wiki/Building.
Alternately, you can run the compiled version of FSEParser to avoid having to install any other dependancies. The latest compiled version can be downloaded here:

https://github.com/dlcowen/FSEventsParser/releases

Usage
---------------------
        ==========================================================================
        FSEParser v 4.0 -- provided by G-C Partners, LLC
        ==========================================================================
        Usage: FSEParser_V4 -s SOURCE -o OUTDIR -t SOURCETYPE [folder|image] [-c CASENAME -q REPORT_QUERIES]

        Options:
          -h, --help         show this help message and exit
          -s SOURCE          REQUIRED. The source directory or image containing
                             fsevent files to be parsed
          -o OUTDIR          REQUIRED. The destination directory used to store parsed
                             reports
          -t SOURCETYPE      REQUIRED. The source type to be parsed. Available options
                             are 'folder' or 'image'
          -c CASENAME        OPTIONAL. The name of the current session,
                             used for naming standards. Defaults to 'FSE_Reports'
          -q REPORT_QUERIES  OPTIONAL. The location of the report_queries.json file
                             containing custom report queries to generate targeted
                             reports.

                             
Examples
---------------------
A live system.
> sudo ./FSEParser_V4 -s /.fseventsd -t folder -o /some_folder -c test_case -q report_queries.json

Exported fsevent files
> FSEParser_V4.exe -s E:\My_Exports\.fseventsd -t folder -o E:\My_Out_Folder -q report_queries.json

An image file.
> FSEParser_V4.exe -s E:\001-My_Source_Image.E01 -t image -o E:\My_Out_Folder -c Test_Case 

An attached external device or mounted volume/image.
> FSEParser_V4.exe -s G:\\.fseventsd -t folder -o E:\My_Out_Folder -q report_queries.json

> sudo ./FSEParser_V4 -s /Volumes/USBDISK/.fseventsd -t folder -o /some_folder -c test_case -q report_queries.json

Notes
----------------------
- Parsed records can be in excess of 1 million records.
- The script does not recursively search subdirectories in the source_dir provided. All FSEvents files including carved gzip if any must be placed in the same directory.
- Currently the script does not perform deduplication. Duplicate records may occur when carved gzips are also parsed.


Ouput Column Reference
-----------------------

event_id: The fsevent record ID in hex and decimal format. The record ID is assigned in chronological order.

node_id: Introduced in HighSierra. The file system node ID (stored in the catalog file for HFS+) of the record fullpath at the time the event was recorded. This value is empty for MacOS versions prior to High Sierra.

fullpath: The record fullpath.

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
- ItemCloned
- LastHardLinkRemoved
- Mount
- Unmount
- EndOfTransaction

approx_dates_plus_minus_one_day: Approximate dates (no times) that the event occurred. The date ranges were pulled using the name of Log files that have the Created flag within an FSEvents file. This value may or may not be off by one day due to timezone variances.

source: The fullpath of the FSEvents file that the record was parsed from.

source_modified_time: The FSEvents source file modified date in UTC.
