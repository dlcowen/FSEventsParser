Overview
---------------------

FSEvents files are written to disk by OS X apis and contain historical records of events that occurred for the partition. They are stored in the root of the partition within the directory '/.fseventsd/'. FSEvent files can be found on the OS X system partition and can also be found on external storage devices that were plugged in to a computer running OS X.

FSEventsParser can be used to parse fsevent files from '/.fseventsd/' folder and also from carved GZIP files. 

The parser outputs parsed information to a tab delimited txt file and an SQLite database. Errors and exceptions are recorded in the exceptions logfile.

Usage
---------------------

    FSEParser v 2.1  -- provided by G-C Partners, LLC
    Run Time:  03/15/2016 20:32:44 [UTC]
    Usage: FSEParser_v2.1.py -c CASENAME -s SOURCEDIR -o OUTDIR
     
    Options:
    -h, --help    show this help message and exit
    -c CASENAME   The name of the current session, used for naming standards
    -s SOURCEDIR  The source directory containing fsevent files to be parsed
    -o OUTDIR     The destination directory used to store parsed reports

Output files:
-	[casename]_FSEvents-Parsed_Records_DB.sqlite: SQLite database containing records parsed from FSEvent files.
-	[casename]_FSEvents-Parsed_Records.tsv: Tab delimited text file containing records parsed from FSEvent files.
-	[casename]_FSEvents-EXCEPTIONS_LOG.txt: Log file containing information related to parsing errors.

Notes
----------------------

- Parsed records can be in excess of 1 million records.
- The script does not recursively search subdirectories. All fsevent files including carved gzip must be place in the same directory.
- Currently the script does not perform deduplication. Duplicate records may occur when carved gzips are also parsed.


Ouput Column Reference
-----------------------

event_id: The event ID for the current record that was parsed. The event ID (WD) is assigned to a file in chronological order, as the event occurred.

mask_hex: The hex representation of the record's mask.

filename: The path and filename stored in the current record.

mask: The record's parsed mask flags. Possible values include: 

    0x00000000: None
    0x00000001: FolderEvent
    0x00000002: Mount
    0x00000004: Unmount
    0x00000020: EndOfTransaction
    0x00000800: LastHardLinkRemoved
    0x00001000: HardLink*
    0x00004000: SymbolicLink
    0x00008000: FileEvent
    0x00010000: PermissionChange
    0x00020000: ExtendedAttrModified
    0x00040000: ExtendedAttrRemoved
    0x00100000: DocumentRevisioning
    0x01000000: Created
    0x02000000: Removed
    0x04000000: InodeMetaMod
    0x08000000: Renamed
    0x10000000: Modified
    0x20000000: Exchange
    0x40000000: FinderInfoMod
    0x80000000: FolderCreated
     
record_end_offset: The end offset of the record within the uncompressed fsevents file.

source: The name of the FSEvents file that the current record was parsed from.

source_modified_time: The source fsevents file modified date.

other_dates: The date(s) that were stripped from the name of a Log file that was modified/created within an FSEvents file. This value is assigned to all records parsed from an FSEvents file and represents the approximate date that the event took place. If no ASL file was found matching the modified/created criteria, this field will be "UNKNOWN". Other dates are pulled from: "private/var/log/asl/YYYY.MM.DD.????.asl", "mobile/Library/Logs/CrashReporter/DiagnosticLogs/security.log.YYYYMMDDTHHMMSSZ", and "log/asl/Logs/aslmanager.YYYYMMDDTHHMMSS-??".





