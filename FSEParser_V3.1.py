#!/usr/bin/python
# FSEvents Parser Python Script
# ------------------------------------------------------
# parse FSEvent records from allocated fsevent files and carved gzip files.
# Outputs parsed information to a tab delimited txt file and SQLite database.
# Errors and exceptions are recorded in the exceptions logfile.

# Copyright 2017 G-C Partners, LLC
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
import ujson
from time import gmtime, strftime
from optparse import OptionParser
import contextlib

VERSION = '3.1'

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

print '=========================================================================='
print 'FSEParser v', VERSION, ' -- provided by G-C Partners, LLC'
print '=========================================================================='


def get_options():
    """Get needed options for processing"""
    usage = "usage: %prog -c CASENAME -q REPORT_QUERIES -s SOURCEDIR -o OUTDIR"
    options = OptionParser(usage=usage)

    options.add_option("-c",
                       action="store",
                       type="string",
                       dest="casename",
                       default=True,
                       help="The name of the current session, used for naming standards")
    options.add_option("-q",
                       action="store",
                       type="string",
                       dest="report_queries",
                       default=True,
                       help="The location of the report_queries.json file containing custom report "
                            "queries to generate targeted reports")
    options.add_option("-s",
                       action="store",
                       type="string",
                       dest="sourcedir",
                       default=True,
                       help="The source directory containing fsevent files to be parsed")
    options.add_option("-o",
                       action="store",
                       type="string",
                       dest="outdir",
                       default=True,
                       help="The destination directory used to store parsed reports")
    # Return options to caller #
    return options


def parse_options():
    # Get options
    options = get_options()
    (opts, args) = options.parse_args()

    # The meta will store all information about the arguments passed #
    meta = {
        'casename': opts.casename,
        'reportqueries': opts.report_queries,
        'sourcedir': opts.sourcedir,
        'outdir': opts.outdir
    }

    # Test arguments passed #
    if opts.report_queries is True:
        options.error("Unable to proceed. report_queries.json was not specified using the -q option. \
            The file can be downloaded from \
            https://github.com/dlcowen/FSEventsParser/blob/master/report_queries.json \
            Then rerun the script and use the -q option to specify the file's location.")
    if len(sys.argv[1:]) == 8 and os.path.exists(meta['sourcedir']) and os.path.exists(
            meta['outdir']) and os.path.exists(meta['reportqueries']):
        pass
    else:
        options.error("Unable to proceed. Check the proper command syntax using -h")
    # Return meta to caller #
    return meta


def main():
    # Process fsevents
    FSEventHandler()

    # Commit transaction
    sqlCon.commit()

    # Close database connection
    sqlCon.close()


def enumerate_flags(flag, f_map):
    # Reset string based flags to null
    f_type = ''
    f_flag = ''
    # Iterate through flags 
    for i in f_map:
        if i & flag:
            if f_map[i] == 'FolderEvent;' or f_map[i] == 'FileEvent;' \
                    or f_map[i] == 'SymbolicLink;' or f_map[i] == 'HardLink;':
                f_type = ''.join([f_type, f_map[i]])
            else:
                f_flag = ''.join([f_flag, f_map[i]])
    return f_type, f_flag


def progress(count, total):
    """
    Handles the progress bar in the console.
    """
    bar_len = 50
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100 * count / float(total), 1)
    bar = '=' * filled_len + '.' * (bar_len - filled_len)

    sys.stdout.write('\tFile %i of %i  [%s] %s%s\r' % (count, total, bar, percents, '%'))
    sys.stdout.flush()


class FSEventHandler:
    def __init__(self):
        self.meta = parse_options()
        # Check json file
        try:
            # Basic json syntax
            try:
                self.r_queries = ujson.load(open(self.meta['reportqueries']))
            except Exception as e:
                self.r_queries = json.load(open(self.meta['reportqueries']))
            # Check to see if required keys are present
            for i in self.r_queries['process_list']:
                i['report_name']
                i['query']
        except Exception as e:
            print('An error occurred while reading the json file. '
                  '%s' % e)
            sys.exit(0)

        self.path = self.meta['sourcedir']

        create_sql_lite_db(self)

        self.files = []
        self.pages = []
        self.src_fullpath = ''
        self.sldVersion = 0

        # Initialize statistic counters
        self.all_records_count = 0
        self.all_files_count = 0
        self.parsed_file_count = 0
        self.error_file_count = 0

        # Try to open the output files
        try:
            # Try to open ouput files
            self.l_all_fsevents = open(
                os.path.join(self.meta['outdir'], self.meta['casename'] + '_All_FSEVENTS.tsv'),
                'wb'
            )
            # Try to open custom report query output files
            for i in self.r_queries['process_list']:
                setattr(
                    self, 'l_' + i['report_name'],
                    open(os.path.join(self.meta['outdir'], self.meta['casename'] + '_' + i['report_name'] + '.tsv'),
                         'wb')
                )

                # Output log file for exceptions
            self.logfile = open(
                os.path.join(self.meta['outdir'], self.meta['casename'] + '_EXCEPTIONS_LOG.txt'),
                'w'
            )
        except Exception as e:
            # print_function error to command prompt if unable to open files
            if 'Permission denied' in e:
                print("%s "
                      "Ensure that you have permissions to write to file\
                       and output file is not in use by another application." % e)
            else:
                print(e)
            sys.exit(0)

        # Begin FSEvent processing
        print('[STARTED]', strftime("%m/%d/%Y %H:%M:%S", gmtime()), "UTC", 'Parsing files')

        self.get_fs_event_files()

        print("\tSee exceptions log for parsing errors.")
        print("\tAll Files Attempted: %d" '\n'
              "\tAll Parsed Files: %d" '\n'
              "\tFiles with Errors: %d"'\n'
              "\tAll Records Parsed: %d"
              % (
               self.all_files_count,
               self.parsed_file_count,
               self.error_file_count,
               self.all_records_count
               ))
        print('[FINISHED]', strftime("%m/%d/%Y %H:%M:%S", gmtime()), "UTC", 'Parsing files')
        print('[STARTED]', strftime("%m/%d/%Y %H:%M", gmtime()), 'UTC', 'Exporting views from database to TSV files')

        # Export report views to output files
        self.export_sql_lite_views()

        print('[FINISHED]', strftime("%m/%d/%Y %H:%M", gmtime()), "UTC", 'Exporting views from database to TSV files')

        # Close output files
        self.l_all_fsevents.close()
        self.logfile.close()

    @contextlib.contextmanager
    def skip_gzip_crc_check(self):
        """
        Context manager that replaces gzip.GzipFile._read_eof with a no-op.
        This is useful when decompressing partial files, something that won't
        work if GzipFile does it's checksum comparison.
        From: https://stackoverflow.com/questions/1732709/unzipping-part-of-a-gz-file-using-python/18602286

        """
        _read_eof = gzip.GzipFile._read_eof
        gzip.GzipFile._read_eof = lambda *args, **kwargs: None
        yield
        gzip.GzipFile._read_eof = _read_eof

    def get_fs_event_files(self):
        """
        GetFsEventFiles will iterate through each file in the fsevents dir provided,
        and attempt to decompress the gzip. If it is unable to decompress,
        it will write an entry in the logfile. If successful, the script will
        check for a sld header in the decompress gzip. If found, the contents of
        the gzip will be placed into a buffer and passed to the next phase of processing.
        """
        # print_function the header columns to the output files
        Output.print_columns(self.l_all_fsevents)
        for i in self.r_queries['process_list']:
            Output.print_columns(getattr(self, 'l_' + i['report_name']))

        # Total number of files in events dir #
        self.t_files = len(os.listdir(self.path))

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

        # iterate through each file in supplied fsevents dir
        for filename in os.listdir(self.path):
            # Variables
            self.all_files_count += 1
            buf = ""

            # Full path to source fsevent file
            self.src_fullpath = os.path.join(self.path, filename)
            # Name of source fsevent file
            self.src_filename = filename
            # UTC mod date of source fsevent file
            self.m_time = str(datetime.datetime.utcfromtimestamp((os.path.getmtime(self.src_fullpath)))) + " [UTC]"

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
                with self.skip_gzip_crc_check():
                    self.files = gzip.GzipFile(self.src_fullpath, "rb")
                    buf = self.files.read()

            except Exception as e:
                # When permission denied is encountered
                if "Permission denied" in e:
                    print("%s" % e)
                    sys.exit(0)
                # Otherwise write error to log file
                else:
                    self.logfile.write(
                        "%s\tError: %s" % (
                            self.src_filename,
                            e
                        )
                    )
                self.error_file_count += 1
                continue

            # Call the progress bar which shows parsing stats
            progress(self.all_files_count, self.t_files)

            # If decompress is success, check for sld headers in the current file
            sld_chk = FSEventHandler.sld_header_search(self, buf, self.src_fullpath)

            # If check for sld returns false, write information to logfile
            if sld_chk is False:
                self.logfile.write(
                    "%s\tError: SLD Header Check Failed. Unable to find a SLD header. Unable to parse File.\n" % (
                        self.src_filename
                    )
                )
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

            # If SLDs were found, pass the decompressed file to be parsed
            FSEventHandler.parse(self, buf)

    def sld_header_search(self, buf, f_name):
        """
        Search within the unzipped file
        for all occurrences of the SLD magic header.
        There can be more than one SLD header in an fsevents file.
        The start and end offsets are stored and used for parsing
        the records contained within each SLD page.
        """
        raw_file = buf
        self.file_size = len(buf)
        sld_count = 0
        self.my_slds = []

        # For each search hit that contains '1SLD' or '2SLD'
        for match in re.finditer('(\x31|\x32)\x53\x4c\x44', raw_file):
            # For each search hit, store offsets in a dict
            # For subsequent page headers found after first only match if
            # value preceding sld match is less than 8 as the highest flag
            # value for the last record within the previous page can only be 7.
            # This avoids false positives where a sld match is found within
            # a record full path.

            off = match.regs[0][0]

            if sld_count == 0:
                # Since this is the first record found
                # Assigned the file size as the end offset of sld [0]
                start_offset = off
                end_offset = self.file_size
            # elif statement checking to see of val preceeding match is < 8
            elif sld_count == 1 and int(raw_file[off - 1:off].encode('hex'), 16) < 8:
                # Since this is second sld found assign end
                # offset to previously found sld
                start_offset = off
                self.my_slds[sld_count - 1]['End Offset'] = start_offset
            elif sld_count > 1 and int(raw_file[off - 1:off].encode('hex'), 16) < 8:
                # For SLDs found after the first two
                # Set the end_off to the curr file size, set start to prev sld end
                end_offset = self.file_size
                self.my_slds[sld_count - 1]['End Offset'] = off
                start_offset = self.my_slds[sld_count - 1]['End Offset']
            else:
                continue
            # Use a temp dict to assignment start and end offsets of current sld location            
            temp_dict = [{'Start Offset': start_offset, 'End Offset': end_offset}]

            # Append current sld information to the SLD dictionary
            self.my_slds.append(temp_dict[0])
            del temp_dict
            sld_count += 1

        if sld_count == 0:
            # Return false to caller so that the next file will be searched
            return False
        else:
            # Return true so that the SLDs found can be parsed
            return True

    def parse(self, buf):
        """
        parse the decompressed fsevent log. First
        finding other dates, then iterating through
        eash sld page found. Then parse records within
        each page.
        """
        # Initialize variables
        pg_count = 0
        self.record_count = 0

        # Call the date finder for current fsevent file
        FSEventHandler.find_date(self, buf)
        self.valid_record_check = True

        # Iterate through sld pages found in current fsevent file
        for i in self.my_slds:
            # Assign current SLD offsets
            start_offset = self.my_slds[pg_count]['Start Offset']
            end_offset = self.my_slds[pg_count]['End Offset']

            # Extract the raw SLD page from the fsevents file
            raw_page = buf[start_offset:end_offset]

            self.page_offset = start_offset

            # Assign SLD version based off magic header in page
            if raw_page[0:4] == "1SLD":
                self.sldVersion = 1
            elif raw_page[0:4] == "2SLD":
                self.sldVersion = 2
            else:
                print "Unknown SLD Version: %s" % (str(raw_page[0:4]))
                sys.exit(1)

            # Pass the raw page + a start offset to find records within page
            FSEventHandler.find_page_records(
                self,
                raw_page,
                start_offset
            )
            # Increment the sld page count by 1
            pg_count += 1

    def find_date(self, raw_file):
        """
        Search within current file for names of log files that are created
        that store the date as a part of its naming
        standard.
        """
        # Reset variables
        self.time_range = []
        prev_temp = 'Unknown'

        # Add previous file's mod timestamp,wd and current file's timestamp,wd
        # to time range
        if not self.is_carved_gzip and self.use_file_mod_dates:
            c_time_1 = str(self.time_range_src_mod[2])[:10].replace("-", ".")
            c_time_2 = str(self.time_range_src_mod[3])[:10].replace("-", ".")

            self.time_range.append([self.time_range_src_mod[0], c_time_1])
            self.time_range.append([self.time_range_src_mod[1], c_time_2])

        # Regex's for logs with dates in name
        regex_1 = "private/var/log/asl/[\x30-\x39]{4}[.][\x30-\x39]{2}[.][\x30-\x39]{2}[.][\x30-\x7a]{2,8}[.]asl"
        regex_2 = "mobile/Library/Logs/CrashReporter/DiagnosticLogs/security[.]log[.][\x30-\x39]{8}T[\x30-\x39]{6}Z"
        regex_3 = "private/var/log/asl/Logs/aslmanager[.][\x30-\x39]{8}T[\x30-\x39]{6}[-][\x30-\x39]{2}"
        regex_4 = "private/var/log/DiagnosticMessages/[\x30-\x39]{4}[.][\x30-\x39]{2}[.][\x30-\x39]{2}[.]asl"
        regex_5 = "private/var/log/com[.]apple[.]clouddocs[.]asl/[\x30-\x39]{4}[.][\x30-\x39]{2}[.][\x30-\x39]{2}[.]asl"
        regex_6 = "private/var/log/powermanagement/[\x30-\x39]{4}[.][\x30-\x39]{2}[.][\x30-\x39]{2}[.]asl"
        regex_7 = "private/var/log/asl/AUX[.][\x30-\x39]{4}[.][\x30-\x39]{2}[.][\x30-\x39]{2}/[0-9]{9}"
        regex_8 = "private/var/audit/[\x30-\x39]{14}[.]not_terminated"

        # Regex that matches only events with created flag
        flag_regex = "[\x00-\xFF]{9}[\x01|\x11|\x21|\x31|\x41|\x51|\x61|\x05|\x15|\x25|\x35|\x45|\x55|\x65]"

        # Concatenating date,flag matching regexes
        # Also grabs working descriptor for record
        m_regex = "(" + regex_1 + "|" + regex_2 + "|" + regex_3 + "|" + regex_4 + "|" + regex_5 + "|" + regex_6 + "|" +\
                  regex_7 + "|" + regex_8 + ")" + flag_regex

        # Start searching within fsevent file for events that match dates regex
        # As the length of each log location is different, create if statements for each
        # so that the date can be pulled from the correct location within the fullpath
        for match in re.finditer(m_regex, raw_file):
            if raw_file[match.regs[0][0]:match.regs[0][0] + 35] == "private/var/log/asl/Logs/aslmanager":
                # Clear timestamp temp variable
                t_temp = ''
                # t_start uses the start offset of the match
                t_start = match.regs[0][0] + 36
                # The date is 8 chars long in the format of yyyymmdd
                t_end = t_start + 8
                # Strip the date from the fsevent file
                t_temp = raw_file[t_start:t_end]
                # Format the date
                t_temp = t_temp[:4] + "." + t_temp[4:6] + "." + t_temp[6:8]
                wd_temp = struct.unpack("<Q", raw_file[match.regs[0][1] - 9:match.regs[0][1] - 1])[0]

            elif raw_file[match.regs[0][0]:match.regs[0][0] + 23] == "private/var/log/asl/AUX":
                # Clear timestamp temp variable
                t_temp = ''
                # t_start uses the start offset of the match
                t_start = match.regs[0][0] + 24
                # The date is 10 chars long in the format of yyyy.mm.dd
                t_end = t_start + 10
                # Strip the date from the fsevent file
                t_temp = raw_file[t_start:t_end]
                wd_temp = struct.unpack("<Q", raw_file[match.regs[0][1] - 9:match.regs[0][1] - 1])[0]

            elif raw_file[match.regs[0][0]:match.regs[0][0] + 19] == "private/var/log/asl":
                # Clear timestamp temp variable
                t_temp = ''
                # t_start uses the start offset of the match
                t_start = match.regs[0][0] + 20
                # The date is 10 chars long in the format of yyyy.mm.dd
                t_end = t_start + 10
                # Strip the date from the fsevent file
                t_temp = raw_file[t_start:t_end]
                wd_temp = struct.unpack("<Q", raw_file[match.regs[0][1] - 9:match.regs[0][1] - 1])[0]

            elif raw_file[match.regs[0][0]:match.regs[0][0] + 4] == "mobi":
                # Clear timestamp temp variable
                t_temp = ''
                # t_start uses the start offset of the match
                t_start = match.regs[0][0] + 62
                # The date is 8 chars long in the format of yyyymmdd
                t_end = t_start + 8
                # Strip the date from the fsevent file
                t_temp = raw_file[t_start:t_end]
                # Format the date
                t_temp = t_temp[:4] + "." + t_temp[4:6] + "." + t_temp[6:8]
                wd_temp = struct.unpack("<Q", raw_file[match.regs[0][1] - 9:match.regs[0][1] - 1])[0]

            elif raw_file[match.regs[0][0]:match.regs[0][0] + 34] == "private/var/log/DiagnosticMessages":
                # Clear timestamp temp variable
                t_temp = ''
                # t_start uses the start offset of the match
                t_start = match.regs[0][0] + 35
                # The date is 10 chars long in the format of yyyy.mm.dd
                t_end = t_start + 10
                # Strip the date from the fsevent file
                t_temp = raw_file[t_start:t_end]
                wd_temp = struct.unpack("<Q", raw_file[match.regs[0][1] - 9:match.regs[0][1] - 1])[0]

            elif raw_file[match.regs[0][0]:match.regs[0][0] + 39] == "private/var/log/com.apple.clouddocs.asl":
                # Clear timestamp temp variable
                t_temp = ''
                # t_start uses the start offset of the match
                t_start = match.regs[0][0] + 40
                # The date is 10 chars long in the format of yyyy.mm.dd
                t_end = t_start + 10
                # Strip the date from the fsevent file
                t_temp = raw_file[t_start:t_end]
                wd_temp = struct.unpack("<Q", raw_file[match.regs[0][1] - 9:match.regs[0][1] - 1])[0]

            elif raw_file[match.regs[0][0]:match.regs[0][0] + 31] == "private/var/log/powermanagement":
                # Clear timestamp temp variable
                t_temp = ''
                # t_start uses the start offset of the match
                t_start = match.regs[0][0] + 32
                # The date is 10 chars long in the format of yyyy.mm.dd
                t_end = t_start + 10
                # Strip the date from the fsevent file
                t_temp = raw_file[t_start:t_end]
                wd_temp = struct.unpack("<Q", raw_file[match.regs[0][1] - 9:match.regs[0][1] - 1])[0]

            elif raw_file[match.regs[0][0]:match.regs[0][0] + 17] == "private/var/audit":
                # Clear timestamp temp variable
                t_temp = ''
                # t_start uses the start offset of the match
                t_start = match.regs[0][0] + 18
                # The date is 8 chars long in the format of yyyymmdd
                t_end = t_start + 8
                # Strip the date from the fsevent file
                t_temp = raw_file[t_start:t_end]
                # Format the date
                t_temp = t_temp[:4] + "." + t_temp[4:6] + "." + t_temp[6:8]
                wd_temp = struct.unpack("<Q", raw_file[match.regs[0][1] - 9:match.regs[0][1] - 1])[0]

            else:
                t_temp = ''
                wd_temp = ''
            # Append date,wd to time range list
            self.time_range.append([wd_temp, t_temp])
        # Sort the time range list by wd
        self.time_range = sorted(self.time_range, key=self.get_key)

        # Call the time range builder to rebuild time range
        self.build_time_range()

    def get_key(self, item):
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
                # Add previous,current wd and previous,current date to temp
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

        # Start,end offset of first record to be parsed within current sld page
        start_offset = 12
        end_offset = 13

        len_buf = len(page_buf)

        # Call the file header parser for current sld page
        try:
            file_header = FsEventFileHeader(
                page_buf[:13],
                self.src_fullpath
            )
        except:
            self.logfile.write(
                "%s\tError: Unable to parse file header at offset %d" % (
                    self.src_filename,
                    page_start_off
                )
            )

        # Account for length of record for different sld versions
        # Prior to HighSierra
        if self.sldVersion == 1:
            binLen = 13
            rBinLen = 12
        # HighSierra
        elif self.sldVersion == 2:
            binLen = 21
            rBinLen = 20
        else:
            pass

        # Iterate through the page.
        # Valid record check should be true while parsing.
        # If an invalid record is encounted (occurs in carved gzips)
        # parsing stops for the current file
        while len_buf > start_offset and self.valid_record_check == True:
            # Grab the first char
            char = page_buf[start_offset:end_offset].encode('hex')
            last_char = char

            if char != '00':
                # Replace non-printable char with nothing
                if str(char).lower() == '0d' or str(char).lower() == '0a':
                    self.logfile.write(
                        "%s\tError: Non-printable char %s in record fullpath at page offset %d. Parser removed char for reporting purposes.\n" % (
                            self.src_filename,
                            char,
                            page_start_off + start_offset
                        )
                    )
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
                # Increment the offsets by binlen, this will be the start of next full path
                start_offset += binLen
                end_offset += binLen

            # Decode fullpath that was stored as hex 
            fullpath = fullpath.decode('hex').replace('\t', '')
            # Store the record length
            record_len = len(fullpath) + binLen

            # Account for records that do not have a fullpath
            if record_len == binLen:
                # Assign NULL as the path
                fullpath = "NULL"
            # Increment the current record count by 1
            self.record_count += 1
            self.all_records_count += 1

            # Assign raw record offsets #
            r_start = start_offset - rBinLen
            r_end = start_offset

            # Strip raw record from page buffer #
            raw_record = page_buf[r_start:r_end]

            # Strip mask from buffer and encode as hex #
            mask_hex = "0x" + raw_record[8:12].encode('hex')

            # Account for carved files when record end offset
            # occurs after the length of the buffer
            if r_end > len_buf:
                continue

            # Set fs_node_id to empty for sld version 1
            # Prior to HighSierra
            if self.sldVersion == 1:
                fs_node_id = ""
            # Assign file system node id if sld version is 2
            # Introduced with HighSierra
            if self.sldVersion == 2:
                fs_node_id = struct.unpack("<q", raw_record[12:])[0]

            record_off = start_offset + page_start_off

            record = FSEventRecord(raw_record, record_off, mask_hex)

            # Check record to see if is valid. Identifies invalid/corrupted
            # that sometimes occur in carved gzip files
            self.valid_record_check = self.check_record(record.mask, fullpath)

            # If record is not valid, stop parsing records in page
            if self.valid_record_check == False or record.wd == 0:
                self.logfile.write(
                    "%s\tError: First invalid record found in carved gzip at offset %d. The remainder of this buffer will not be parsed.\n" % (
                        self.src_filename,
                        page_start_off + start_offset
                    )
                )
                fullpath = ''
                break
            # Otherwise assign attributes and add to outpur reports
            else:
                f_path, f_name = os.path.split(fullpath)
                dates = self.apply_date(record.wd)
                # Assign our current records attributes
                attributes = {
                    'id': record.wd,
                    'id_hex': record.wd_hex,
                    'fullpath': fullpath,
                    'filename': f_name,
                    'type': record.mask[0],
                    'flags': record.mask[1],
                    'approx_dates(plus_minus_one_day)': dates,
                    'mask': mask_hex,
                    'node_id': fs_node_id,
                    'record_end_offset': record_off,
                    'source': self.src_fullpath,
                    'source_modified_time': self.m_time
                }

                output = Output(attributes)

                # print_function the parsed record to output file
                output.print_function(self.l_all_fsevents)

                fullpath = ''

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
            fol_cr_err = "FolderEvent" in mask[0] and "Created" in mask[1] and "FolderCreated" not in mask[1]
            fil_cr_err = "FileEvent" in mask[0] and "FolderCreated" in mask[1]
            lnk_err = "SymbolicLink" in mask[0] and "HardLink" in mask[0]
            h_lnk_err = "HardLink" not in mask[0] and "LastHardLink" in mask[1]
            h_lnk_err_2 = "LastHardLink" in mask[1] and ";Removed" not in mask[1]
            n_used_err = "NOT_USED-0x0" in mask[1]
            ver_error = "ItemCloned" in mask[1] and self.sldVersion == 1

            # Check for decode errors
            try:
                fullpath.decode('utf-8')
            except Exception as e:
                decode_error = True

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
                if i[0] < wd < i[1]:
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

    def export_sql_lite_views(self):
        # Gather the names of report views in the db
        sqlTran.execute("SELECT name FROM sqlite_master WHERE type='view'")
        view_names = sqlTran.fetchall()

        # Export report views to tsv files
        for i in view_names:
            print("\tExporting table %s from database" % (i[0]))
            query = "SELECT * FROM %s ORDER BY %s.id ASC" % (i[0], i[0])
            sqlTran.execute(query)
            rows = sqlTran.fetchall()

            # Get outfile to write to
            out_file = getattr(self, "l_" + i[0])

            # For each row join using tab and output to file
            for r in rows:
                values = []
                for cell in r:
                    values.append(cell)
                row = u'\t'.join(values)
                row = row
                out_file.write(row.encode('utf-8'))


class FsEventFileHeader:
    def __init__(self, buf, filename):
        # Name and path of current source fsevent file
        self.src_fullpath = filename
        # Page header '1SLD' or '2SLD'
        self.signature = buf[0:4]
        # Unknown raw values in SLD header
        self.unknown_raw = buf[4:8]
        # Unknown hex version 
        self.unknown_hex = buf[4:8].encode("hex")
        # Unknown integer version
        self.unknown_int = struct.unpack("<I", self.unknown_raw)[0]
        # Size of current SLD page
        self.filesize = struct.unpack("<I", buf[8:12])[0]


class FSEventRecord(dict):
    def __init__(self, buf, offset, mask_hex):
        # Offset of the record within the fsevent file
        self.file_offset = offset
        # Raw record hex version
        self.header_hex = binascii.b2a_hex(buf)
        # Record wd or event id
        self.wd = struct.unpack("<Q", buf[0:8])[0]
        # Record wd hex version with byte order reversed
        self.wd_hex = "0x" + (buf[7] + buf[6] + buf[5] + buf[4] + buf[3] + buf[2] + buf[1] + buf[0]).encode('hex')
        # Enumerate mask flags, string version
        self.mask = enumerate_flags(
            struct.unpack(">I", buf[8:12])[0],
            EVENTMASK
        )


class Output(dict):
    COLUMNS = [
        u'id',
        u'id_hex',
        u'fullpath',
        u'filename',
        u'type',
        u'flags',
        u'approx_dates(plus_minus_one_day)',
        u'mask',
        u'node_id',
        u'record_end_offset',
        u'source',
        u'source_modified_time'
    ]

    @staticmethod
    def print_columns(outfile):
        values = []
        for key in Output.COLUMNS:
            values.append(str(key))
        row = "\t".join(values)
        outfile.write(row)

    def __init__(self, attribs):
        self.update(attribs)

    def print_function(self, outfile):
        values = []
        vals_to_insert = ''

        for key in Output.COLUMNS:
            values.append(str(self[key]))

        out = "\t".join(values)

        # Write current row to outfile
        outfile.write(out)

        # Replace any Quotes in parsed record with double quotes
        for i in values:
            vals_to_insert += i.replace('"', '""') + '","'

        vals_to_insert = '"' + vals_to_insert[:-3] + '"'
        insert_sqlite_db(vals_to_insert)


def create_sql_lite_db(self):
    db_filename = os.path.join(self.meta['outdir'], self.meta['casename'] + '_FSEvents.sqlite')
    table_schema = "CREATE TABLE [fsevents](\
                  [id] [TEXT] NULL,\
                  [id_hex] [TEXT] NULL,\
                  [fullpath] [TEXT] NULL,\
                  [filename] [TEXT] NULL,\
                  [type] [TEXT] NULL,\
                  [flags] [TEXT] NULL,\
                  [approx_dates(plus_minus_one_day)] [TEXT] NULL, \
                  [mask] [TEXT] NULL, \
                  [node_id] [TEXT] NULL, \
                  [record_end_offset] [TEXT] NULL,\
                  [source] [TEXT] NULL, \
                  [source_modified_time] [TEXT] NULL)"

    # if database already exists delete it
    try:
        if os.path.isfile(db_filename):
            os.remove(db_filename)
        # create database file if it doesn't exist
        db_is_new = not os.path.exists(db_filename)
    except:
        print("FSEvents Parser Python Script, Version %s \
        -----------ERROR------------\
        The following output file is currently in use by another program.\
        -%s\
        Please ensure that the file is closed. Then rerun the parser." % (VERSION, db_filename))
        sys.exit(0)

    # setup global
    global sqlCon

    with sqlite3.connect(db_filename):
        sqlCon = sqlite3.connect(os.path.join("", db_filename))

    if db_is_new:
        # Create table if it's a new database
        sqlCon.execute(table_schema)

        # run queries in report queries list
        # to add report database views
        for i in self.r_queries['process_list']:
            # Try to execute the query
            try:
                sqlCon.execute(i['query'])
            except Exception as e:
                print("SQLite error when executing query in json file. %s" % e)
                sys.exit(0)

    # setup global
    global sqlTran

    # setup transaction cursor and return it
    sqlTran = sqlCon.cursor()


def insert_sqlite_db(vals_to_insert):
    insert_statement = "\
        insert into fsevents (\
        [id],\
        [id_hex],\
        [fullpath],\
        [filename],\
        [type],\
        [flags],\
        [approx_dates(plus_minus_one_day)],\
        [mask],\
        [node_id],\
        [record_end_offset],\
        [source],\
        [source_modified_time]\
        ) values (" + vals_to_insert + ")"

    try:
        sqlTran.execute(insert_statement)
    except Exception as e:
        print("insert failed!: %s" % vals_to_insert)


if __name__ == '__main__':
    main()
