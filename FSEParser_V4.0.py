#!/usr/bin/python

# FSEvents Parser Python Script
# ------------------------------------------------------
# Parse FSEvent records from allocated fsevent files and carved gzip files.
# Outputs parsed information to a tab delimited txt file and SQLite database.
# Errors and exceptions are recorded in the exceptions logfile.

# Copyright 2019 G-C Partners, LLC
# Nicole Ibrahim
#
# G-C Partners licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

import sys
import os
import struct
import binascii
import gzip
import re
import datetime
import sqlite3
import json
import io
from time import (gmtime, strftime)
from optparse import OptionParser
import contextlib

try:
    from dfvfs.analyzer import analyzer
    from dfvfs.lib import definitions
    from dfvfs.path import factory as path_spec_factory
    from dfvfs.volume import tsk_volume_system
    from dfvfs.resolver import resolver
    from dfvfs.lib import raw
    from dfvfs.helpers import source_scanner
    DFVFS_IMPORT = True
    IMPORT_ERROR = None
except ImportError as exp:
    DFVFS_IMPORT = False
    IMPORT_ERROR =("\n%s\n\
        You have specified the source type as image but DFVFS \n\
        is not installed and is required for image support. \n\
        To install DFVFS please refer to \n\
        http://www.hecfblog.com/2015/12/how-to-install-dfvfs-on-windows-without.html" % (exp))

VERSION = '4.0'

EVENTMASK = {
    0x00000000: 'None;',
    0x00000001: 'FolderEvent;',
    0x00000002: 'Mount;',
    0x00000004: 'Unmount;',
    0x00000020: 'EndOfTransaction;',
    0x00000800: 'LastHardLinkRemoved;',
    0x00001000: 'HardLink;',
    0x00004000: 'SymbolicLink;',
    0x00008000: 'FileEvent;',
    0x00010000: 'PermissionChange;',
    0x00020000: 'ExtendedAttrModified;',
    0x00040000: 'ExtendedAttrRemoved;',
    0x00100000: 'DocumentRevisioning;',
    0x00400000: 'ItemCloned;',  # macOS HighSierra
    0x01000000: 'Created;',
    0x02000000: 'Removed;',
    0x04000000: 'InodeMetaMod;',
    0x08000000: 'Renamed;',
    0x10000000: 'Modified;',
    0x20000000: 'Exchange;',
    0x40000000: 'FinderInfoMod;',
    0x80000000: 'FolderCreated;',
    0x00000008: 'NOT_USED-0x00000008;',
    0x00000010: 'NOT_USED-0x00000010;',
    0x00000040: 'NOT_USED-0x00000040;',
    0x00000080: 'NOT_USED-0x00000080;',
    0x00000100: 'NOT_USED-0x00000100;',
    0x00000200: 'NOT_USED-0x00000200;',
    0x00000400: 'NOT_USED-0x00000400;',
    0x00002000: 'NOT_USED-0x00002000;',
    0x00080000: 'NOT_USED-0x00080000;',
    0x00200000: 'NOT_USED-0x00200000;',
    0x00800000: 'NOT_USED-0x00800000;'
}

print('\n==========================================================================')
print('FSEParser v {} -- provided by G-C Partners, LLC'.format(VERSION))
print('==========================================================================')


def get_options():
    """
    Get needed options for processing
    """
    usage = "usage: %prog -s SOURCE -o OUTDIR -t SOURCETYPE [folder|image] [-c CASENAME -q REPORT_QUERIES]"
    options = OptionParser(usage=usage)
    options.add_option("-s",
                       action="store",
                       type="string",
                       dest="source",
                       default=False,
                       help="REQUIRED. The source directory or image containing fsevent files to be parsed")
    options.add_option("-o",
                       action="store",
                       type="string",
                       dest="outdir",
                       default=False,
                       help="REQUIRED. The destination directory used to store parsed reports")
    options.add_option("-t",
                       action="store",
                       type="string",
                       dest="sourcetype",
                       default=False,
                       help="REQUIRED. The source type to be parsed. Available options are 'folder' or 'image'")
    options.add_option("-c",
                       action="store",
                       type="string",
                       dest="casename",
                       default=False,
                       help="OPTIONAL. The name of the current session, \
                       used for naming standards. Defaults to 'FSE_Reports'")
    options.add_option("-q",
                       action="store",
                       type="string",
                       dest="report_queries",
                       default=False,
                       help="OPTIONAL. The location of the report_queries.json file \
                       containing custom report queries to generate targeted reports."
                       )

    # Return options to caller #
    return options


def parse_options():
    """
    Capture and return command line arguments.
    """
    # Get options
    options = get_options()
    (opts, args) = options.parse_args()

    # The meta will store all information about the arguments passed #
    meta = {
        'casename': opts.casename,
        'reportqueries': opts.report_queries,
        'sourcetype': opts.sourcetype,
        'source': opts.source,
        'outdir': opts.outdir
    }

    # Print help if no options are provided
    if len(sys.argv[1:]) == 0:
        options.print_help()
        sys.exit(1)
    # Test required arguments
    if meta['source'] is False or meta['outdir'] is False or meta['sourcetype'] is False:
        options.error('Unable to proceed. The following parameters '
            'are required:\n-s SOURCE\n-o OUTDIR\n-t SOURCETYPE')

    if not os.path.exists(meta['source']):
        options.error("Unable to proceed. \n\n%s does not exist.\n" % meta['source'])

    if not os.path.exists(meta['outdir']):
        options.error("Unable to proceed. \n\n%s does not exist.\n" % meta['outdir'])
        
    if meta['reportqueries'] and not os.path.exists(meta['reportqueries']):
        options.error("Unable to proceed. \n\n%s does not exist.\n" % meta['reportqueries'])

    if meta['sourcetype'].lower() != 'folder' and meta['sourcetype'].lower() != 'image':
        options.error(
            'Unable to proceed. \n\nIncorrect source type provided: "%s". The following are valid options:\
            \n -t folder\n -t image\n' % (meta['sourcetype']))

    if meta['sourcetype'] == 'image' and DFVFS_IMPORT is False:
        options.error(IMPORT_ERROR)

    if meta['reportqueries'] ==False:
        print('[Info]: Report queries file not specified using the -q option. Custom reports will not be generated.')
        
    if meta['casename'] is False:
        print('[Info]: No casename specified using -c. Defaulting to "FSE_Reports".')
        meta['casename'] = 'FSE_Reports'

    # Return meta to caller #
    return meta


def main():
    """
    Call the main processes.
    """
    # Process fsevents
    FSEventHandler()

    # Commit transaction
    SQL_CON.commit()

    # Close database connection
    SQL_CON.close()


def enumerate_flags(flag, f_map):
    """
    Iterate through record flag mappings and enumerate.
    """
    # Reset string based flags to null
    f_type = ''
    f_flag = ''
    # Iterate through flags
    for i in f_map:
        if i & flag:
            if f_map[i] == 'FolderEvent;' or \
                    f_map[i] == 'FileEvent;' or \
                    f_map[i] == 'SymbolicLink;' or \
                    f_map[i] == 'HardLink;':
                f_type = ''.join([f_type, f_map[i]])
            else:
                f_flag = ''.join([f_flag, f_map[i]])
    return f_type, f_flag


def progress(count, total):
    """
    Handles the progress bar in the console.
    """
    bar_len = 45
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100 * count / float(total), 1)
    p_bar = '=' * filled_len + '.' * (bar_len - filled_len)
    try:
        sys.stdout.write('  File {} of {}  [{}] {}{}\r'.format(count, total, p_bar, percents, '%'))
    except:
        pass
    sys.stdout.flush()


class FSEventHandler():
    """
    FSEventHandler iterates through and parses fsevents.
    """

    def __init__(self):
        """
        """
        self.meta = parse_options()
        if self.meta['reportqueries']:
            # Check json file
            try:
                # Basic json syntax
                self.r_queries = json.load(open(self.meta['reportqueries']))
                # Check to see if required keys are present
                for i in self.r_queries['process_list']:
                    i['report_name']
                    i['query']
            except Exception as exp:
                print('An error occurred while reading the json file. \n{}'.format(str(exp)))
                sys.exit(0)
        else:
            # if report queries option was not specified
            self.r_queries = False

        self.path = self.meta['source']

        create_sqlite_db(self)

        self.files = []
        self.pages = []
        self.src_fullpath = ''
        self.dls_version = 0

        # Initialize statistic counters
        self.all_records_count = 0
        self.all_files_count = 0
        self.parsed_file_count = 0
        self.error_file_count = 0

        # Try to open the output files
        try:
            # Try to open ouput files
            self.l_all_fsevents = open(
                os.path.join(self.meta['outdir'], self.meta['casename'], 'All_FSEVENTS.tsv'),
                'wb'
            )
            # Process report queries output files
            # if option was specified.
            if self.r_queries:
                # Try to open custom report query output files
                for i in self.r_queries['process_list']:
                    r_file = os.path.join(self.meta['outdir'], self.meta['casename'], i['report_name'] + '.tsv')
                    if os.path.exists(r_file):
                        os.remove(r_file)
                    setattr(self, 'l_' + i['report_name'], open(r_file, 'wb'))

            # Output log file for exceptions
            l_file = os.path.join(self.meta['outdir'], self.meta['casename'], 'EXCEPTIONS_LOG.txt')
            self.logfile = open(l_file, 'w')
        except Exception as exp:
            # Print error to command prompt if unable to open files
            if 'Permission denied' in str(exp):
                print('{}\nEnsure that you have permissions to write to file '
                      '\nand output file is not in use by another application.\n'.format(str(exp)))
            else:
                print(exp)
            sys.exit(0)

        # Begin FSEvent processing

        print('\n[STARTED] {} UTC Parsing files.'.format(strftime("%m/%d/%Y %H:%M:%S", gmtime())))

        if self.meta['sourcetype'] == 'image':
            self._get_fsevent_image_files()
        elif self.meta['sourcetype'] == 'folder':
            self._get_fsevent_files()
            print('\n  All Files Attempted: {}\n  All Parsed Files: {}\n  Files '
                  'with Errors: {}\n  All Records Parsed: {}'.format(
                self.all_files_count,
                self.parsed_file_count,
                self.error_file_count,
                self.all_records_count))

        print('[FINISHED] {} UTC Parsing files.\n'.format(strftime("%m/%d/%Y %H:%M:%S", gmtime())))

        print('[STARTED] {} UTC Sorting fsevents table in Database.'.format(strftime("%m/%d/%Y %H:%M:%S", gmtime())))

        row_count = reorder_sqlite_db(self)
        if row_count != 0:
            print('[FINISHED] {} UTC Sorting fsevents table in Database.\n'.format(strftime("%m/%d/%Y %H:%M:%S", gmtime())))
    
            print('[STARTED] {} UTC Exporting fsevents table from Database.'.format(
                strftime("%m/%d/%Y %H:%M:%S", gmtime())))
    
            self.export_fsevent_report(self.l_all_fsevents, row_count)
    
            print('[FINISHED] {} UTC Exporting fsevents table from Database.\n'.format(
                strftime("%m/%d/%Y %H:%M:%S", gmtime())))
    
            if self.r_queries:
                print('[STARTED] {} UTC Exporting views from database '
                      'to TSV files.'.format(strftime("%m/%d/%Y %H:%M:%S", gmtime())))
                for i in self.r_queries['process_list']:
                    Output.print_columns(getattr(self, 'l_' + i['report_name']))
                # Export report views to output files
                self.export_sqlite_views()
                print('[FINISHED] {} UTC Exporting views from database '
                      'to TSV files.\n'.format(strftime("%m/%d/%Y %H:%M:%S", gmtime())))
    
            print("  Exception log and Reports exported to:\n  '{}'\n".format(os.path.join(self.meta['outdir'], self.meta['casename'])))
    
            # Close output files
            self.l_all_fsevents.close()
            self.logfile.close()
        else:
            print('[FINISHED] {} UTC No records were parsed.\n'.format(strftime("%m/%d/%Y %H:%M:%S", gmtime())))
            print('Nothing to export.\n')


    @contextlib.contextmanager
    def skip_gzip_check(self):
        """
        Context manager that replaces gzip.GzipFile._read_eof with a no-op.
        This is useful when decompressing partial files, something that won't
        work if GzipFile does it's checksum comparison.
        stackoverflow.com/questions/1732709/unzipping-part-of-a-gz-file-using-python/18602286
        """
        _read_eof = gzip._GzipReader._read_eof
        gzip.GzipFile._read_eof = lambda *args, **kwargs: None
        yield
        gzip.GzipFile._read_eof = _read_eof


    def _get_fsevent_files(self):
        """
        get_fsevent_files will iterate through each file in the fsevents dir provided,
        and attempt to decompress the gzip. If it is unable to decompress,
        it will write an entry in the logfile. If successful, the script will
        check for a DLS header signature in the decompress gzip. If found, the contents of
        the gzip will be placed into a buffer and passed to the next phase of processing.
        """
        # Print the header columns to the output files
        Output.print_columns(self.l_all_fsevents)

        # Total number of files in events dir #
        t_files = len(os.listdir(self.path))
        for filename in os.listdir(self.path):
            if filename == 'fseventsd-uuid':
                t_files -= 1
        self.time_range_src_mod = []
        prev_mod_date = "Unknown"
        prev_last_wd = 0
        c_last_wd = 0

        # Uses file mod dates to generate time ranges by default unless
        # files are carved or mod dates lost due to exporting
        self.use_file_mod_dates = True

        # Run simple test to see if file mod dates
        # should be used to generate time ranges
        # In some instances fsevent files may not have
        # their original mod times preserved on export
        # This code will flag true when the same date and hour
        # exists for the first file and the last file
        # in the provided source fsevents folder
        first = os.path.join(self.path, os.listdir(self.path)[0])
        last = os.path.join(self.path, os.listdir(self.path)[len(os.listdir(self.path)) - 1])
        first = os.path.getmtime(first)
        last = os.path.getmtime(last)
        first = str(datetime.datetime.utcfromtimestamp(first))[:14]
        last = str(datetime.datetime.utcfromtimestamp(last))[:14]

        if first == last:
            self.use_file_mod_dates = False

        # Iterate through each file in supplied fsevents dir
        for filename in os.listdir(self.path):
            if filename == 'fseventsd-uuid':
                continue
            # Variables
            self.all_files_count += 1

            # Call the progress bar which shows parsing stats
            progress(self.all_files_count, t_files)

            buf = ""

            # Full path to source fsevent file
            self.src_fullpath = os.path.join(self.path, filename)
            # Name of source fsevent file
            self.src_filename = filename
            # UTC mod date of source fsevent file
            self.m_time = os.path.getmtime(self.src_fullpath)
            self.m_time = str(datetime.datetime.utcfromtimestamp((self.m_time))) + " [UTC]"

            # Regex to match against source fsevent log filename
            regexp = re.compile(r'^.*[\][0-9a-fA-F]{16}$')

            # Test to see if fsevent file name matches naming standard
            # if not, assume this is a carved gzip
            if len(self.src_filename) == 16 and regexp.search(filename) is not None:
                c_last_wd = int(self.src_filename, 16)
                self.time_range_src_mod = prev_last_wd, c_last_wd, prev_mod_date, self.m_time
                self.is_carved_gzip = False
            else:
                self.is_carved_gzip = True

            # Attempt to decompress the fsevent archive
            try:
                with self.skip_gzip_check():
                    self.files = gzip.GzipFile(self.src_fullpath, "rb")
                    buf = self.files.read()

            except Exception as exp:
                # When permission denied is encountered
                if "Permission denied" in str(exp) and not os.path.isdir(self.src_fullpath):
                    print('\nEnsure that you have permissions to read '
                          'from {}\n{}\n'.format(self.path, str(exp)))
                    sys.exit(0)
                # Otherwise write error to log file
                else:
                    self.logfile.write(
                        "%s\tError: Error while decompressing FSEvents file.%s\n" % (
                            self.src_filename,
                            str(exp)
                        )
                    )
                self.error_file_count += 1
                continue

            # If decompress is success, check for DLS headers in the current file
            dls_chk = FSEventHandler.dls_header_search(self, buf, self.src_fullpath)

            # If check for DLS returns false, write information to logfile
            if dls_chk is False:
                self.logfile.write('%s\tInfo: DLS Header Check Failed. Unable to find a '
                                   'DLS header. Unable to parse File.\n' % (self.src_filename))
                # Continue to the next file in the fsevents directory
                self.error_file_count += 1
                continue

            self.parsed_file_count += 1

            # Accounts for fsevent files that get flushed to disk
            # at the same time. Usually the result of a shutdown
            # or unmount
            if not self.is_carved_gzip and self.use_file_mod_dates:
                prev_mod_date = self.m_time
                prev_last_wd = int(self.src_filename, 16)

            # If DLSs were found, pass the decompressed file to be parsed
            FSEventHandler.parse(self, buf)


    def _get_fsevent_image_files(self):
        """
        get_fsevent_files will iterate through each file in the fsevents dir
        and attempt to decompress the gzip. If it is unable to decompress,
        it will write an entry in the logfile. If successful, the script will
        check for a DLS header signature in the decompress gzip. If found, the contents of
        the gzip will be placed into a buffer and passed to the next phase of processing.
        """
        # Print the header columns to the output file
        Output.print_columns(self.l_all_fsevents)
                
        scan_path_spec = None
        scanner = source_scanner.SourceScanner()
        scan_context = source_scanner.SourceScannerContext()
        scan_context.OpenSourcePath(self.meta['source'])

        scanner.Scan(
            scan_context,
            scan_path_spec=scan_path_spec
        )

        for file_system_path_spec, file_system_scan_node in scan_context._file_system_scan_nodes.items():
            t_files = 0
            self.all_files_count = 0
            self.error_file_count = 0
            self.all_records_count = 0
            self.parsed_file_count = 0
            
            try:
                location = file_system_path_spec.parent.location
            except:
                location = file_system_path_spec.location
                
            print("  Processing Volume {}.\n".format(location))

            fs_event_path_spec = path_spec_factory.Factory.NewPathSpec(
                file_system_path_spec.type_indicator,
                parent=file_system_path_spec.parent,
                location="/.fseventsd"
            )

            file_entry = resolver.Resolver.OpenFileEntry(
                fs_event_path_spec
            )
            
            if file_entry != None:

                t_files = file_entry.number_of_sub_file_entries
                for sub_file_entry in file_entry.sub_file_entries:
                    if sub_file_entry.name == 'fseventsd-uuid':
                        t_files -= 1

                self.time_range_src_mod = []
                prev_mod_date = "Unknown"
                prev_last_wd = 0
                c_last_wd = 0
                counter = 0

                # Uses file mod dates to generate time ranges by default unless
                # files are carved or mod dates lost due to exporting
                self.use_file_mod_dates = True

                # Iterate through each file in supplied fsevents dir
                for sub_file_entry in file_entry.sub_file_entries:
                    if sub_file_entry.name == 'fseventsd-uuid':
                        continue
                    # Variables
                    counter += 1
                    self.all_files_count += 1

                    # Call the progress bar which shows parsing stats
                    progress(counter, t_files)

                    buf = ""

                    # Name of source fsevent file
                    self.src_filename = sub_file_entry.name
                    self.src_fullpath = self.meta['source'] + ": " + location + sub_file_entry.path_spec.location

                    stat_object = sub_file_entry.GetStat()

                    # UTC mod date of source fsevent file
                    self.m_time = datetime.datetime.fromtimestamp(
                        stat_object.mtime).strftime(
                        '%Y-%m-%d %H:%M:%S') + " [UTC]"

                    # Regex to match against source fsevent log filename
                    regexp = re.compile(r'^.*[\][0-9a-fA-F]{16}$')

                    # Test to see if fsevent file name matches naming standard
                    # if not, assume this is a carved gzip
                    if len(self.src_filename) == 16 and regexp.search(self.src_filename) is not None:
                        c_last_wd = int(self.src_filename, 16)
                        self.time_range_src_mod = prev_last_wd, c_last_wd, prev_mod_date, self.m_time
                        self.is_carved_gzip = False
                    else:
                        self.is_carved_gzip = True
                    file_object = sub_file_entry.GetFileObject()

                    compressedFile = io.StringIO.BytesIO()
                    compressedFile.write(file_object.read())
                    compressedFile.seek(0)
                    # Attempt to decompress the fsevent archive
                    try:
                        with self.skip_gzip_check():
                            self.files = gzip.GzipFile(fileobj=compressedFile, mode='rb')
                            buf = self.files.read()

                    except Exception as exp:
                        self.logfile.write(
                            "%s\tError: Error while decompressing FSEvents file.%s\n" % (
                                self.src_filename,
                                str(exp)
                            )
                        )
                        self.error_file_count += 1
                        continue

                    # If decompress is success, check for DLS headers in the current file
                    dls_chk = FSEventHandler.dls_header_search(self, buf, self.src_filename)

                    # If check for DLS returns false, write information to logfile
                    if dls_chk is False:
                        self.logfile.write('%s\tInfo: DLS Header Check Failed. Unable to find a '
                                           'DLS header. Unable to parse File.\n' % (self.src_filename))
                        # Continue to the next file in the fsevents directory
                        self.error_file_count += 1
                        continue

                    self.parsed_file_count += 1

                    # Accounts for fsevent files that get flushed to disk
                    # at the same time. Usually the result of a shutdown
                    # or unmount
                    if not self.is_carved_gzip and self.use_file_mod_dates:
                        prev_mod_date = self.m_time
                        prev_last_wd = int(self.src_filename, 16)

                    # If DLSs were found, pass the decompressed file to be parsed
                    FSEventHandler.parse(self, buf)
            
            else:
                print('Unable to process volume or no fsevent files found')
                continue

            print('\n\n  All Files Attempted: {}\n  All Parsed Files: {}\n  Files '
                  'with Errors: {}\n  All Records Parsed: {}'.format(
                self.all_files_count,
                self.parsed_file_count,
                self.error_file_count,
                self.all_records_count))


    def dls_header_search(self, buf, f_name):
        """
        Search within the unzipped file
        for all occurrences of the DLS magic header.
        There can be more than one DLS header in an fsevents file.
        The start and end offsets are stored and used for parsing
        the records contained within each DLS page.
        """
        self.file_size = len(buf)
        self.my_dls = []

        raw_file = buf
        dls_count = 0
        start_offset = 0
        end_offset = 0

        while end_offset != self.file_size:
            try:
                start_offset = end_offset
                page_len = struct.unpack("<I", raw_file[start_offset + 8:start_offset + 12])[0]
                end_offset = start_offset + page_len

                if raw_file[start_offset:start_offset + 4] == b'1SLD' or raw_file[start_offset:start_offset + 4] == b'2SLD':
                    self.my_dls.append({'Start Offset': start_offset, 'End Offset': end_offset})
                    dls_count += 1
                else:
                    self.logfile.write("%s: Error in length of page when finding page headers." % (f_name))
                    break
            except:
                self.logfile.write("%s: Error in length of page when finding page headers." % (f_name))
                break

        if dls_count == 0:
            # Return false to caller so that the next file will be searched
            return False
        else:
            # Return true so that the DLSs found can be parsed
            return True


    def parse(self, buf):
        """
        Parse the decompressed fsevent log. First
        finding other dates, then iterating through
        eash DLS page found. Then parse records within
        each page.
        """
        # Initialize variables
        pg_count = 0

        # Call the date finder for current fsevent file
        FSEventHandler.find_date(self, buf)
        self.valid_record_check = True

        # Iterate through DLS pages found in current fsevent file
        for i in self.my_dls:
            # Assign current DLS offsets
            start_offset = self.my_dls[pg_count]['Start Offset']
            end_offset = self.my_dls[pg_count]['End Offset']

            # Extract the raw DLS page from the fsevents file
            raw_page = buf[start_offset:end_offset]

            self.page_offset = start_offset

            # Reverse byte stream to match byte order little-endian
            m_dls_chk = raw_page[0:4]
            # Assign DLS version based off magic header in page
            if m_dls_chk == b"1SLD":
                self.dls_version = 1
            elif m_dls_chk == b"2SLD":
                self.dls_version = 2
            else:
                self.logfile.write("%s: Unknown DLS Version." % (self.src_filename))
                break

            # Pass the raw page + a start offset to find records within page
            FSEventHandler.find_page_records(
                self,
                raw_page,
                start_offset
            )
            # Increment the DLS page count by 1
            pg_count += 1


    def find_date(self, raw_file):
        """
        Search within current file for names of log files that are created
        that store the date as a part of its naming
        standard.
        """
        # Reset variables
        self.time_range = []

        # Add previous file's mod timestamp, wd and current file's timestamp, wd
        # to time range
        if not self.is_carved_gzip and self.use_file_mod_dates:
            c_time_1 = str(self.time_range_src_mod[2])[:10].replace("-", ".")
            c_time_2 = str(self.time_range_src_mod[3])[:10].replace("-", ".")

            self.time_range.append([self.time_range_src_mod[0], c_time_1])
            self.time_range.append([self.time_range_src_mod[1], c_time_2])

        # Regex's for logs with dates in name
        regex_1 = ("private/var/log/asl/[\x30-\x39]{4}[.][\x30-\x39]{2}" +
                   "[.][\x30-\x39]{2}[.][\x30-\x7a]{2,8}[.]asl")
        regex_2 = ("mobile/Library/Logs/CrashReporter/DiagnosticLogs/security[.]log" +
                   "[.][\x30-\x39]{8}T[\x30-\x39]{6}Z")
        regex_3 = ("private/var/log/asl/Logs/aslmanager[.][\x30-\x39]{8}T[\x30-\x39]" +
                   "{6}[-][\x30-\x39]{2}")
        regex_4 = ("private/var/log/DiagnosticMessages/[\x30-\x39]{4}[.][\x30-\x39]{2}" +
                   "[.][\x30-\x39]{2}[.]asl")
        regex_5 = ("private/var/log/com[.]apple[.]clouddocs[.]asl/[\x30-\x39]{4}[.]" +
                   "[\x30-\x39]{2}[.][\x30-\x39]{2}[.]asl")
        regex_6 = ("private/var/log/powermanagement/[\x30-\x39]{4}[.][\x30-\x39]{2}[.]" +
                   "[\x30-\x39]{2}[.]asl")
        regex_7 = ("private/var/log/asl/AUX[.][\x30-\x39]{4}[.][\x30-\x39]{2}[.]" +
                   "[\x30-\x39]{2}/[0-9]{9}")
        regex_8 = "private/var/audit/[\x30-\x39]{14}[.]not_terminated"

        # Regex that matches only events with created flag
        flag_regex = ("[\x00-\xFF]{9}[\x01|\x11|\x21|\x31|\x41|\x51|\x61|\x05|\x15|" +
                      "\x25|\x35|\x45|\x55|\x65]")

        # Concatenating date, flag matching regexes
        # Also grabs working descriptor for record
        m_regex = "(" + regex_1 + "|" + regex_2 + "|" + regex_3 + "|" + regex_4 + "|" + regex_5
        m_regex = m_regex + "|" + regex_6 + "|" + regex_7 + "|" + regex_8 + ")" + flag_regex

        # Start searching within fsevent file for events that match dates regex
        # As the length of each log location is different, create if statements for each
        # so that the date can be pulled from the correct location within the fullpath

        #decode to latin as it preveserves all lengths (1 byte == 1 character)
        raw_file_ascii = raw_file.decode("latin_1")
        for match in re.finditer(m_regex, raw_file_ascii):
            if raw_file_ascii[match.regs[0][0]:match.regs[0][0] + 35] == "private/var/log/asl/Logs/aslmanager":
                # Clear timestamp temp variable
                t_temp = ''
                # t_start uses the start offset of the match
                t_start = match.regs[0][0] + 36
                # The date is 8 chars long in the format of yyyymmdd
                t_end = t_start + 8
                # Strip the date from the fsevent file
                t_temp = raw_file_ascii[t_start:t_end]
                # Format the date
                t_temp = t_temp[:4] + "." + t_temp[4:6] + "." + t_temp[6:8]
                wd_temp = struct.unpack("<Q", raw_file[match.regs[0][1] - 9:match.regs[0][1] - 1])[0]
            elif raw_file_ascii[match.regs[0][0]:match.regs[0][0] + 23] == "private/var/log/asl/AUX":
                # Clear timestamp temp variable
                t_temp = ''
                # t_start uses the start offset of the match
                t_start = match.regs[0][0] + 24
                # The date is 10 chars long in the format of yyyy.mm.dd
                t_end = t_start + 10
                # Strip the date from the fsevent file
                t_temp = raw_file_ascii[t_start:t_end]
                wd_temp = struct.unpack("<Q", raw_file[match.regs[0][1] - 9:match.regs[0][1] - 1])[0]
            elif raw_file_ascii[match.regs[0][0]:match.regs[0][0] + 19] == "private/var/log/asl":
                # Clear timestamp temp variable
                t_temp = ''
                # t_start uses the start offset of the match
                t_start = match.regs[0][0] + 20
                # The date is 10 chars long in the format of yyyy.mm.dd
                t_end = t_start + 10
                # Strip the date from the fsevent file
                t_temp = raw_file_ascii[t_start:t_end]
                wd_temp = struct.unpack("<Q", raw_file[match.regs[0][1] - 9:match.regs[0][1] - 1])[0]
            elif raw_file_ascii[match.regs[0][0]:match.regs[0][0] + 4] == "mobi":
                # Clear timestamp temp variable
                t_temp = ''
                # t_start uses the start offset of the match
                t_start = match.regs[0][0] + 62
                # The date is 8 chars long in the format of yyyymmdd
                t_end = t_start + 8
                # Strip the date from the fsevent file
                t_temp = raw_file_ascii[t_start:t_end]
                # Format the date
                t_temp = t_temp[:4] + "." + t_temp[4:6] + "." + t_temp[6:8]
                wd_temp = struct.unpack("<Q", raw_file[match.regs[0][1] - 9:match.regs[0][1] - 1])[0]
            elif raw_file_ascii[match.regs[0][0]:match.regs[0][0] + 34] == "private/var/log/DiagnosticMessages":
                # Clear timestamp temp variable
                t_temp = ''
                # t_start uses the start offset of the match
                t_start = match.regs[0][0] + 35
                # The date is 10 chars long in the format of yyyy.mm.dd
                t_end = t_start + 10
                # Strip the date from the fsevent file
                t_temp = raw_file_ascii[t_start:t_end]
                wd_temp = struct.unpack("<Q", raw_file[match.regs[0][1] - 9:match.regs[0][1] - 1])[0]
            elif raw_file_ascii[match.regs[0][0]:match.regs[0][0] + 39] == "private/var/log/com.apple.clouddocs.asl":
                # Clear timestamp temp variable
                t_temp = ''
                # t_start uses the start offset of the match
                t_start = match.regs[0][0] + 40
                # The date is 10 chars long in the format of yyyy.mm.dd
                t_end = t_start + 10
                # Strip the date from the fsevent file
                t_temp = raw_file_ascii[t_start:t_end]
                wd_temp = struct.unpack("<Q", raw_file[match.regs[0][1] - 9:match.regs[0][1] - 1])[0]
            elif raw_file_ascii[match.regs[0][0]:match.regs[0][0] + 31] == "private/var/log/powermanagement":
                # Clear timestamp temp variable
                t_temp = ''
                # t_start uses the start offset of the match
                t_start = match.regs[0][0] + 32
                # The date is 10 chars long in the format of yyyy.mm.dd
                t_end = t_start + 10
                # Strip the date from the fsevent file
                t_temp = raw_file_ascii[t_start:t_end]
                wd_temp = struct.unpack("<Q", raw_file[match.regs[0][1] - 9:match.regs[0][1] - 1])[0]
            elif raw_file_ascii[match.regs[0][0]:match.regs[0][0] + 17] == "private/var/audit":
                # Clear timestamp temp variable
                t_temp = ''
                # t_start uses the start offset of the match
                t_start = match.regs[0][0] + 18
                # The date is 8 chars long in the format of yyyymmdd
                t_end = t_start + 8
                # Strip the date from the fsevent file
                t_temp = raw_file_ascii[t_start:t_end]
                # Format the date
                t_temp = t_temp[:4] + "." + t_temp[4:6] + "." + t_temp[6:8]
                wd_temp = struct.unpack("<Q", raw_file[match.regs[0][1] - 9:match.regs[0][1] - 1])[0]
            else:
                t_temp = ''
                wd_temp = ''
            # Append date, wd to time range list
            self.time_range.append([wd_temp, t_temp])
        # Sort the time range list by wd
        self.time_range = sorted(self.time_range, key=self.get_key)

        # Call the time range builder to rebuild time range
        self.build_time_range()


    def get_key(self, item):
        """
        Return the key in the time range item provided.
        """
        return item[0]

    def build_time_range(self):
        """
        Rebuilds the time range list to
        include the previous and current working descriptor
        as well as the previous and current date found
        """
        prev_date = '0'
        prev_wd = 0
        temp = []

        # Iterate through each in time range list
        for i in self.time_range:
            # Len is 7 when prev_date is 'Unknown'
            if len(prev_date) == 7:
                p_date = 0
                c_date = i[1][:10].replace(".", "")
            # When current date is 'Unknown'
            if len(i[1]) == 7:
                p_date = prev_date[:10].replace(".", "")
                c_date = 0
            # When both dates are known
            if len(prev_date) != 7 and len(i[1]) != 7:
                p_date = prev_date[:10].replace(".", "")
                c_date = i[1][:10].replace(".", "")
            # Bypass a date when current date is less than prev date
            if int(c_date) < int(p_date):
                prev_wd = prev_wd
                prev_date = prev_date
            else:
                # Reassign prev_date to 'Unknown'
                if prev_date == '0':
                    prev_date = 'Unknown'
                # Add previous, current wd and previous, current date to temp
                temp.append([prev_wd, i[0], prev_date, i[1]])
                prev_wd = i[0]
                prev_date = i[1]
        # Assign temp list to time range list
        self.time_range = temp


    def find_page_records(self, page_buf, page_start_off):
        """
        Input values are starting offset of current page and
        end offset of current page within the current fsevent file
        find_page_records will identify all records within a given page.
        """

        # Initialize variables
        fullpath = ''
        char = ''

        # Start, end offset of first record to be parsed within current DLS page
        start_offset = 12
        end_offset = 13

        len_buf = len(page_buf)

        # Call the file header parser for current DLS page
        try:
            FsEventFileHeader(
                page_buf[:13],
                self.src_fullpath
            )
        except:
            self.logfile.write(
                "%s\tError: Unable to parse file header at offset %d\n" % (
                    self.src_filename,
                    page_start_off
                )
            )

        # Account for length of record for different DLS versions
        # Prior to HighSierra
        if self.dls_version == 1:
            bin_len = 13
            rbin_len = 12
        # HighSierra
        elif self.dls_version == 2:
            bin_len = 21
            rbin_len = 20
        else:
            pass

        # Iterate through the page.
        # Valid record check should be true while parsing.
        # If an invalid record is encounted (occurs in carved gzips)
        # parsing stops for the current file
        while len_buf > start_offset and self.valid_record_check:
            # Grab the first char
            char = page_buf[start_offset:end_offset].hex()

            if char != '00':
                # Replace non-printable char with nothing
                if str(char).lower() == '0d' or str(char).lower() == '0a':
                    self.logfile.write('%s\tInfo: Non-printable char %s in record fullpath at '
                                       'page offset %d. Parser removed char for reporting '
                                       'purposes.\n' % \
                                       (self.src_filename, char, page_start_off + start_offset))
                    char = ''
                # Append the current char to the full path for current record
                fullpath = fullpath + char
                # Increment the offsets by one
                start_offset += 1
                end_offset += 1
                # Continue the while loop
                continue
            elif char == '00':
                # When 00 is found, then it is the end of fullpath
                # Increment the offsets by bin_len, this will be the start of next full path
                start_offset += bin_len
                end_offset += bin_len

            # Decode fullpath that was stored as hex
            fullpath = bytes.fromhex(fullpath).decode("utf-8").replace('\t', '')
            # Store the record length
            record_len = len(fullpath) + bin_len

            # Account for records that do not have a fullpath
            if record_len == bin_len:
                # Assign NULL as the path
                fullpath = "NULL"

            # Assign raw record offsets #
            r_start = start_offset - rbin_len
            r_end = start_offset

            # Strip raw record from page buffer #
            raw_record = page_buf[r_start:r_end]

            # Strip mask from buffer and encode as hex #
            mask_hex = "0x" + raw_record[8:12].hex()

            # Account for carved files when record end offset
            # occurs after the length of the buffer
            if r_end > len_buf:
                continue

            # Set fs_node_id to empty for DLS version 1
            # Prior to HighSierra
            if self.dls_version == 1:
                fs_node_id = ""
            # Assign file system node id if DLS version is 2
            # Introduced with HighSierra
            if self.dls_version == 2:
                fs_node_id = struct.unpack("<q", raw_record[12:])[0]

            record_off = start_offset + page_start_off

            record = FSEventRecord(raw_record, record_off, mask_hex)

            # Check record to see if is valid. Identifies invalid/corrupted
            # that sometimes occur in carved gzip files
            self.valid_record_check = self.check_record(record.mask, fullpath)

            # If record is not valid, stop parsing records in page
            if self.valid_record_check is False or record.wd == 0:
                self.logfile.write('%s\tInfo: First invalid record found in carved '
                                   'gzip at offset %d. The remainder of this buffer '
                                   'will not be parsed.\n' % \
                                   (self.src_filename, page_start_off + start_offset))
                fullpath = ''
                break
            # Otherwise assign attributes and add to outpur reports
            else:
                f_path, f_name = os.path.split(fullpath)
                dates = self.apply_date(record.wd)
                # Assign our current records attributes
                attributes = {
                    'id': record.wd,
                    'id_hex': record.wd_hex.decode("ascii") + " (" + str(record.wd) + ")",
                    'fullpath': fullpath,
                    'filename': f_name,
                    'type': record.mask[0],
                    'flags': record.mask[1],
                    'approx_dates_plus_minus_one_day': dates,
                    'mask': mask_hex,
                    'node_id': fs_node_id,
                    'record_end_offset': record_off,
                    'source': self.src_fullpath,
                    'source_modified_time': self.m_time
                }

                output = Output(attributes)

                # Print the parsed record to output file
                output.append_row()

                fullpath = ''
            # Increment the current record count by 1
            self.all_records_count += 1


    def check_record(self, mask, fullpath):
        """
        Checks for conflicts in the record's flags
        to determine if the record is valid to limit the
        number of invalid records in parsed output.
        Applies only to carved gzip
        """
        if self.is_carved_gzip:
            decode_error = False
            # Flag conflicts
            # These flag combinations can not exist together
            type_err = "FolderEvent" in mask[0] and "FileEvent" in mask[0]
            fol_cr_err = "FolderEvent" in mask[0] and "Created" in mask[1] and \
                         "FolderCreated" not in mask[1]
            fil_cr_err = "FileEvent" in mask[0] and "FolderCreated" in mask[1]
            lnk_err = "SymbolicLink" in mask[0] and "HardLink" in mask[0]
            h_lnk_err = "HardLink" not in mask[0] and "LastHardLink" in mask[1]
            h_lnk_err_2 = "LastHardLink" in mask[1] and ";Removed" not in mask[1]
            n_used_err = "NOT_USED-0x0" in mask[1]
            ver_error = "ItemCloned" in mask[1] and self.dls_version == 1

            # If any error exists return false to caller
            if type_err or \
                    fol_cr_err or \
                    fil_cr_err or \
                    lnk_err or \
                    h_lnk_err or \
                    h_lnk_err_2 or \
                    n_used_err or \
                    decode_error or \
                    ver_error:
                return False
            else:
                # Record passed tests and may be valid
                # return true so that record is included in output reports
                return True
        else:
            # Return true. fsevent file was not identified as being carved
            return True


    def apply_date(self, wd):
        """
        Applies the approximate date to
        the current record by comparing thewd
        to what is stored in the time range list.
        """
        t_range_count = len(self.time_range)
        count = 1
        c_mod_date = str(self.m_time)[:10].replace("-", ".")

        # No dates were found. Return source mod date
        if len(self.time_range) == 0 and not self.is_carved_gzip and self.use_file_mod_dates:
            return c_mod_date
        # If dates were found
        elif len(self.time_range) != 0 and not self.is_carved_gzip:

            # Iterate through the time range list
            # and assign the time range based off the
            # wd/record event id.
            for i in self.time_range:
                # When record id falls between the previous
                # id and the current id within the time range list
                if wd > i[0] and wd < i[1]:
                    # When the previous date is the same as current
                    if i[2] == i[3]:
                        return i[2]
                    # Otherwise return the date range
                    else:
                        return i[2] + " - " + i[3]
                # When event id matches previous wd in list
                # assign previous date
                elif wd == i[0]:
                    return str(i[2])
                # When event id matches current wd in list
                # assign current date
                elif wd == i[1]:
                    return str(i[3])
                # When the event id is greater than the last in list
                # assign return source mod date
                elif count == t_range_count and wd >= i[1] and self.use_file_mod_dates:
                    return c_mod_date
                else:
                    count = count + 1
                    continue
        else:
            return "Unknown"


    def export_fsevent_report(self, outfile, row_count):
        """
        Export rows from fsevents table in DB to tab delimited report.
        """
        counter = 0

        query = 'SELECT \
                id_hex, \
                node_id, \
                fullpath, \
                type, \
                flags, \
                approx_dates_plus_minus_one_day, \
                source, \
                source_modified_time \
                FROM fsevents_sorted_by_event_id'

        SQL_TRAN.execute(query)

        while row_count > counter:
            row = SQL_TRAN.fetchone()
            values = []
            for cell in row:
                if type(cell) is str or type(cell) is unicode:
                    try:
                        values.append(cell)
                    except:
                        print(row_count)
                        print(type(cell))
                        print(cell)
                        print(row)
                        values.append("ERROR_IN_VALUE")
                else:
                    try:
                        values.append(unicode(cell))
                    except:
                        print(row_count)
                        print(type(cell))
                        print(cell)
                        print(row)
                        values.append("ERROR_IN_VALUE")
            m_row = u'\t'.join(values)
            m_row = m_row + u'\n'
            outfile.write(m_row.encode("utf-8"))
            counter = counter + 1


    def export_sqlite_views(self):
        """
        Exports sqlite views from database if -q is set.
        """
        # Gather the names of report views in the db
        SQL_TRAN.execute("SELECT name FROM sqlite_master WHERE type='view'")
        view_names = SQL_TRAN.fetchall()

        # Export report views to tsv files
        for i in view_names:

            query = "SELECT * FROM %s" % (i[0])
            SQL_TRAN.execute(query)
            row = ' '
            # Get outfile to write to
            outfile = getattr(self, "l_" + i[0])
            row = SQL_TRAN.fetchone()
            if row is None:
                print("  No records found in view {}. Nothing to export".format(i[0]))
                outfile.close()
                os.remove(outfile.name)
            else:
                print("  Exporting view {} from database".format(i[0]))
                # For each row join using tab and output to file
                while row is not None:
                    values = []
                    try:
                        for cell in row:
                            if type(cell) is str or type(cell) is unicode:
                                values.append(cell)
                            else:
                                values.append(unicode(cell))
                    except:
                        values.append("ERROR_IN_VALUE")
                        print("ERROR: ", row)
                    m_row = u'\t'.join(values)
                    m_row = m_row + u'\n'
                    outfile.write(m_row.encode("utf-8"))
                    row = SQL_TRAN.fetchone()


class FsEventFileHeader():
    """
    FSEvent file header structure.
        Each page within the decompressed begins with DLS1 or DLS2
        It is stored using a byte order of little-endian.
    """

    def __init__(self, buf, filename):
        """
        """
        # Name and path of current source fsevent file
        self.src_fullpath = filename
        # Page header 'DLS1' or 'DLS2'
        # Was written to disk using little-endian
        # Byte stream contains either "1SLD" or "2SLD", reversing order
        self.signature = buf[4] + buf[3] + buf[2] + buf[1]
        # Unknown raw values in DLS header
        # self.unknown_raw = buf[4:8]
        # Unknown hex version
        # self.unknown_hex = buf[4:8].encode("hex")
        # Unknown integer version
        # self.unknown_int = struct.unpack("<I", self.unknown_raw)[0]
        # Size of current DLS page
        self.filesize = struct.unpack("<I", buf[8:12])[0]


class FSEventRecord(dict):
    """
    FSEvent record structure.
    """
    def __init__(self, buf, offset, mask_hex):
        """
        """
        # Offset of the record within the fsevent file
        self.file_offset = offset
        # Raw record hex version
        self.header_hex = binascii.b2a_hex(buf)
        # Record wd or event id
        self.wd = struct.unpack("<Q", buf[0:8])[0]
        # Record wd_hex
        wd_buf = bytearray(buf[0:8])
        wd_buf.reverse()
        self.wd_hex = binascii.b2a_hex(wd_buf)
        # Enumerate mask flags, string version
        self.mask = enumerate_flags(
            struct.unpack(">I", buf[8:12])[0],
            EVENTMASK
        )


class Output(dict):
    """
    Output class handles outputting parsed
    fsevent records to report files.
    """
    COLUMNS = [
                u'id',
                u'id_hex',
                u'fullpath',
                u'filename',
                u'type',
                u'flags',
                u'approx_dates_plus_minus_one_day',
                u'mask',
                u'node_id',
                u'record_end_offset',
                u'source',
                u'source_modified_time'
    ]
    R_COLUMNS = [
                u'event_id',
                u'node_id',
                u'fullpath',
                u'type',
                u'flags',
                u'approx_dates_plus_minus_one_day',
                u'source',
                u'source_modified_time'
    ]


    def __init__(self, attribs):
        """
        Update column values.
        """
        self.update(attribs)


    @staticmethod
    def print_columns(outfile):
        """
        Output column header to report files.
        """
        values = []
        for key in Output.R_COLUMNS:
            values.append(str(key))
        row = '\t'.join(values)
        row = row + '\n'
        outfile.write(row.encode("utf8"))


    def append_row(self):
        """
        Output parsed fsevents row to database.
        """
        values = []
        vals_to_insert = ''

        for key in Output.COLUMNS:
            values.append(str(self[key]))

        # Replace any Quotes in parsed record with double quotes
        for i in values:
            vals_to_insert += i.replace('"', '""') + '","'

        vals_to_insert = '"' + vals_to_insert[:-3] + '"'
        insert_sqlite_db(vals_to_insert)


def create_sqlite_db(self):
    """
    Creates our output database for parsed records
    and connects to it.
    """
    db_filename = os.path.join(self.meta['outdir'], self.meta['casename'], 'FSEvents.sqlite')
    table_schema = "CREATE TABLE [fsevents](\
                  [id] [BLOB] NULL, \
                  [id_hex] [TEXT] NULL, \
                  [fullpath] [TEXT] NULL, \
                  [filename] [TEXT] NULL, \
                  [type] [TEXT] NULL, \
                  [flags] [TEXT] NULL, \
                  [approx_dates_plus_minus_one_day] [TEXT] NULL, \
                  [mask] [TEXT] NULL, \
                  [node_id] [TEXT] NULL, \
                  [record_end_offset] [TEXT] NULL, \
                  [source] [TEXT] NULL, \
                  [source_modified_time] [TEXT] NULL)"
    if not os.path.isdir(os.path.join(self.meta['outdir'], self.meta['casename'])):
        os.makedirs(os.path.join(self.meta['outdir'], self.meta['casename']))

    # If database already exists delete it
    try:
        if os.path.isfile(db_filename):
            os.remove(db_filename)
        # Create database file if it doesn't exist
        db_is_new = not os.path.exists(db_filename)
    except:
        print("\nThe following output file is currently in use by "
              "another program.\n -{}\nPlease ensure that the file is closed."
              " Then rerun the parser.".format(db_filename))
        sys.exit(0)

    # Setup global
    global SQL_CON

    SQL_CON = sqlite3.connect(os.path.join("", db_filename))

    if db_is_new:
        # Create table if it's a new database
        SQL_CON.execute(table_schema)
        if self.r_queries:
            # Run queries in report queries list
            # to add report database views
            for i in self.r_queries['process_list']:
                # Try to execute the query
                cols = 'id_hex, \
                    node_id, \
                    fullpath, \
                    type, \
                    flags, \
                    approx_dates_plus_minus_one_day, \
                    source, \
                    source_modified_time'

                query = i['query'].split("*")
                query = query[0] + cols + query[1]

                try:
                    SQL_CON.execute(query)
                except Exception as exp:
                    print("SQLite error when executing query in json file. {}".format(str(exp)))
                    sys.exit(0)

    # Setup global
    global SQL_TRAN

    # Setup transaction cursor and return it
    SQL_TRAN = SQL_CON.cursor()


def insert_sqlite_db(vals_to_insert):
    """
    Insert parsed fsevent record values into database.
    """
    insert_statement = "\
        insert into fsevents (\
        [id], \
        [id_hex], \
        [fullpath], \
        [filename], \
        [type], \
        [flags], \
        [approx_dates_plus_minus_one_day], \
        [mask], \
        [node_id], \
        [record_end_offset], \
        [source], \
        [source_modified_time]\
        ) values (" + vals_to_insert + ")"

    try:
        SQL_TRAN.execute(insert_statement)
    except Exception as exp:
        print("insert failed!: {}".format(exp))


def reorder_sqlite_db(self):
    """
    Order database table rows by id.
    Returns
        count: The number of rows in the table
    """
    query = "CREATE TABLE [fsevents_sorted_by_event_id](\
                  [id] [BLOB] NULL, \
                  [id_hex] [TEXT] NULL, \
                  [fullpath] [TEXT] NULL, \
                  [filename] [TEXT] NULL, \
                  [type] [TEXT] NULL, \
                  [flags] [TEXT] NULL, \
                  [approx_dates_plus_minus_one_day] [TEXT] NULL, \
                  [mask] [TEXT] NULL, \
                  [node_id] [TEXT] NULL, \
                  [record_end_offset] [TEXT] NULL, \
                  [source] [TEXT] NULL, \
                  [source_modified_time] [TEXT] NULL)"

    SQL_TRAN.execute(query)

    query = "INSERT INTO fsevents_sorted_by_event_id ( \
                  id, \
                  id_hex, \
                  fullpath, \
                  filename, \
                  type, \
                  flags, \
                  approx_dates_plus_minus_one_day, \
                  mask, \
                  node_id, \
                  record_end_offset, \
                  source, \
                  source_modified_time) \
                  SELECT id,\
                  id_hex,\
                  fullpath,\
                  filename,\
                  type,flags,\
                  approx_dates_plus_minus_one_day,\
                  mask,\
                  node_id,\
                  record_end_offset,\
                  source,\
                  source_modified_time \
                  FROM fsevents ORDER BY id_hex;"

    SQL_TRAN.execute(query)

    count = SQL_TRAN.lastrowid

    return count


if __name__ == '__main__':
    """
    Init checks to see if running appropriate python version.
    If it is, start the parser.
    """
    main()
