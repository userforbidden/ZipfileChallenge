import argparse
import struct
import io
import os 
import stat
import time 
import sys 

structEndArchive = b"<4s4H2LH"
stringEndArchive = b"PK\005\006"
sizeEndCentDir = struct.calcsize(structEndArchive)

_ECD_SIZE = 5
_ECD_OFFSET = 6
_ECD_COMMENT_SIZE = 7
# These last two indices are not part of the structure as defined in the
# spec, but they are used internally by this module as a convenience
_ECD_COMMENT = 8
_ECD_LOCATION = 9

# The "central directory" structure, magic number, size, and indices
# of entries in the structure (section V.F in the format document)
structCentralDir = "<4s4B4HL2L5H2L"
stringCentralDir = b"PK\001\002"
sizeCentralDir = struct.calcsize(structCentralDir)

# indexes of entries in the central directory structure
_CD_SIGNATURE = 0
_CD_CREATE_VERSION = 1
_CD_CREATE_SYSTEM = 2
_CD_EXTRACT_VERSION = 3
_CD_EXTRACT_SYSTEM = 4
_CD_FLAG_BITS = 5
_CD_COMPRESS_TYPE = 6
_CD_TIME = 7
_CD_DATE = 8
_CD_CRC = 9
_CD_COMPRESSED_SIZE = 10
_CD_UNCOMPRESSED_SIZE = 11
_CD_FILENAME_LENGTH = 12
_CD_EXTRA_FIELD_LENGTH = 13
_CD_COMMENT_LENGTH = 14
_CD_DISK_NUMBER_START = 15
_CD_INTERNAL_FILE_ATTRIBUTES = 16
_CD_EXTERNAL_FILE_ATTRIBUTES = 17
_CD_LOCAL_HEADER_OFFSET = 18

# The "local file header" structure, magic number, size, and indices
# (section V.A in the format document)
structFileHeader = "<4s2B4HL2L2H"
stringFileHeader = b"PK\003\004"
sizeFileHeader = struct.calcsize(structFileHeader)

# ZIP64_LIMIT = (1 << 31) - 1
# ZIP_FILECOUNT_LIMIT = (1 << 16) - 1
# ZIP_MAX_COMMENT = (1 << 16) - 1

# constants for Zip file compression methods
ZIP_STORED = 0
ZIP_DEFLATED = 8
ZIP_BZIP2 = 12
ZIP_LZMA = 14
# Other ZIP compression methods not supported

DEFAULT_VERSION = 20
ZIP64_VERSION = 45
BZIP2_VERSION = 46
LZMA_VERSION = 63
# we recognize (but not necessarily support) all features up to that version
MAX_EXTRACT_VERSION = 63

class BadZipFile(Exception):
    pass

class LargeZipFile(Exception):
    """
    Raised when writing a zipfile, the zipfile requires ZIP64 extensions
    and those extensions are disabled.
    """

def _EndRecData(fpin):
    """Return data from the "End of Central Directory" record, or None.
    The data is a list of the nine items in the ZIP "End of central dir"
    record followed by a tenth item, the file seek offset of this record."""
    # Determine file size
    fpin.seek(0, 2)
    filesize = fpin.tell()

    # Check to see if this is ZIP file with no archive comment (the
    # "end of central directory" structure should be the last item in the
    # file if this is the case).
    try:
        fpin.seek(-sizeEndCentDir, 2)
    except OSError:
        return None
    data = fpin.read()
    if (len(data) == sizeEndCentDir and
        data[0:4] == stringEndArchive and
        data[-2:] == b"\000\000"):
        # the signature is correct and there's no comment, unpack structure
        endrec = struct.unpack(structEndArchive, data)
        endrec=list(endrec)

        # Append a blank comment and record start offset
        endrec.append(b"")
        endrec.append(filesize - sizeEndCentDir)

        return endrec

    # Either this is not a ZIP file, or it is a ZIP file with an archive
    # comment.  Search the end of the file for the "end of central directory"
    # record signature. The comment is the last item in the ZIP file and may be
    # up to 64K long.  It is assumed that the "end of central directory" magic
    # number does not appear in the comment.
    maxCommentStart = max(filesize - (1 << 16) - sizeEndCentDir, 0)
    fpin.seek(maxCommentStart, 0)
    data = fpin.read()
    start = data.rfind(stringEndArchive)
    if start >= 0:
        # found the magic number; attempt to unpack and interpret
        recData = data[start:start+sizeEndCentDir]
        if len(recData) != sizeEndCentDir:
            # Zip file is corrupted.
            return None
        endrec = list(struct.unpack(structEndArchive, recData))
        commentSize = endrec[_ECD_COMMENT_SIZE] #as claimed by the zip file
        comment = data[start+sizeEndCentDir:start+sizeEndCentDir+commentSize]
        endrec.append(comment)
        endrec.append(maxCommentStart + start)

        return endrec

    # Unable to find a valid end of central directory structure
    return None
class ZipInfo (object):
    """Class with attributes describing each file in the ZIP archive."""

    __slots__ = (
        'orig_filename',
        'filename',
        'date_time',
        'compress_type',
        '_compresslevel',
        'comment',
        'extra',
        'create_system',
        'create_version',
        'extract_version',
        'reserved',
        'flag_bits',
        'volume',
        'internal_attr',
        'external_attr',
        'header_offset',
        'CRC',
        'compress_size',
        'file_size',
        '_raw_time',
        'isDirectory',
    )

    def __init__(self, filename="NoName", date_time=(1980,1,1,0,0,0)):
        self.orig_filename = filename   # Original file name in archive

        # Terminate the file name at the first null byte.  Null bytes in file
        # names are used as tricks by viruses in archives.
        null_byte = filename.find(chr(0))
        if null_byte >= 0:
            filename = filename[0:null_byte]
        # This is used to ensure paths in generated ZIP files always use
        # forward slashes as the directory separator, as required by the
        # ZIP format specification.
        if os.sep != "/" and os.sep in filename:
            filename = filename.replace(os.sep, "/")

        self.filename = filename        # Normalized file name
        self.date_time = date_time      # year, month, day, hour, min, sec

        if date_time[0] < 1980:
            raise ValueError('ZIP does not support timestamps before 1980')

        # Standard values:
        self.compress_type = ZIP_STORED # Type of compression for the file
        self._compresslevel = None      # Level for the compressor
        self.comment = b""              # Comment for each file
        self.extra = b""                # ZIP extra data
        if sys.platform == 'win32':
            self.create_system = 0          # System which created ZIP archive
        else:
            # Assume everything else is unix-y
            self.create_system = 3          # System which created ZIP archive
        self.create_version = DEFAULT_VERSION  # Version which created ZIP archive
        self.extract_version = DEFAULT_VERSION # Version needed to extract archive
        self.reserved = 0               # Must be zero
        self.flag_bits = 0              # ZIP flag bits
        self.volume = 0                 # Volume number of file header
        self.internal_attr = 0          # Internal attributes
        self.external_attr = 0          # External file attributes
        self.compress_size = 0          # Size of the compressed file
        self.file_size = 0              # Size of the uncompressed file
        self.isDirectory = False        # flag to identify if it's a directory
        # Other attributes are set by class ZipFile:
        # header_offset         Byte offset to the file header
        # CRC                   CRC-32 of the uncompressed file


    def FileHeader(self, zip64=None):
        """Return the per-file header as a bytes object."""
        dt = self.date_time
        dosdate = (dt[0] - 1980) << 9 | dt[1] << 5 | dt[2]
        dostime = dt[3] << 11 | dt[4] << 5 | (dt[5] // 2)
        if self.flag_bits & 0x08:
            # Set these to zero because we write them after the file data
            CRC = compress_size = file_size = 0
        else:
            CRC = self.CRC
            compress_size = self.compress_size
            file_size = self.file_size

        extra = self.extra

        min_version = 0
        self.extract_version = max(min_version, self.extract_version)
        self.create_version = max(min_version, self.create_version)
        filename, flag_bits = self._encodeFilenameFlags()
        header = struct.pack(structFileHeader, stringFileHeader,
                             self.extract_version, self.reserved, flag_bits,
                             self.compress_type, dostime, dosdate, CRC,
                             compress_size, file_size,
                             len(filename), len(extra))
        return header + filename + extra

    def _decodeExtra(self):
        # Try to decode the extra field.
        extra = self.extra
        unpack = struct.unpack
        while len(extra) >= 4:
            tp, ln = unpack('<HH', extra[:4])
            if ln+4 > len(extra):
                raise BadZipFile("Corrupt extra field %04x (size=%d)" % (tp, ln))
            if tp == 0x0001:
                data = extra[4:ln+4]
                # ZIP64 extension (large files and/or large archives)
                try:
                    if self.file_size in (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF):
                        field = "File size"
                        self.file_size, = unpack('<Q', data[:8])
                        data = data[8:]
                    if self.compress_size == 0xFFFF_FFFF:
                        field = "Compress size"
                        self.compress_size, = unpack('<Q', data[:8])
                        data = data[8:]
                    if self.header_offset == 0xFFFF_FFFF:
                        field = "Header offset"
                        self.header_offset, = unpack('<Q', data[:8])
                except struct.error:
                    raise BadZipFile(f"Corrupt zip64 extra field. "
                                     f"{field} not found.") from None

            extra = extra[ln+4:]

   
    def is_dir(self):
        """Return True if this archive member is a directory."""
        self.isDirectory == True
        return self.filename[-1] == '/'

class ZipFile:
    fp = None
    def __init__(self,file,mode="r"):
        self.filelist = []
        self.mode = mode
        self.debug = 0
        self.NameToInfo = {} 
        
        if isinstance(file, os.PathLike):
            file = os.fspath(file)
        
        if isinstance(file, str):
            # No, it's a filename
            self._filePassed = 0
            self.filename = file
            modeDict = {'r' : 'rb', 'w': 'w+b', 'x': 'x+b', 'a' : 'r+b',
                        'r+b': 'w+b', 'w+b': 'wb', 'x+b': 'xb'}
            filemode = modeDict[mode]
            while True:
                try:
                    self.fp = io.open(file, filemode)
                except OSError:
                    if filemode in modeDict:
                        filemode = modeDict[filemode]
                        continue
                    raise
                break
        else:
            self._filePassed = 1
            self.fp = file
            self.filename = getattr(file, 'name', None)
        
        self._fileRefCnt = 1

        self._GetContents()
    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        """Close the file, and for mode 'w', 'x' and 'a' write the ending
        records."""
        if self.fp is None:
            return
        fp = self.fp
        self.fp = None
        self._fpclose(fp)
    
    def _fpclose(self, fp):
        assert self._fileRefCnt > 0
        self._fileRefCnt -= 1
        if not self._fileRefCnt and not self._filePassed:
            fp.close()

    def _GetContents(self):
        fp = self.fp
        try:
            endrec = _EndRecData(fp)
        except OSError:
            raise BadZipFile("File is not a zip file ")
        # if self.debug > 1:
        size_cd = endrec[_ECD_SIZE]             # bytes in central directory
        offset_cd = endrec[_ECD_OFFSET]         # offset of central directory
        self._comment = endrec[_ECD_COMMENT]    # archive comment

        # "concat" is zero, unless zip was concatenated to another file
        concat = endrec[_ECD_LOCATION] - size_cd - offset_cd

        if self.debug > 2:
            inferred = concat + offset_cd
            print("given, inferred, offset", offset_cd, inferred, concat)
        # self.start_dir:  Position of start of central directory
        self.start_dir = offset_cd + concat
        if self.start_dir < 0:
            raise BadZipFile("Bad offset for central directory")
        fp.seek(self.start_dir, 0)
        data = fp.read(size_cd)
        fp = io.BytesIO(data)
        total = 0
        while total < size_cd:
            centdir = fp.read(sizeCentralDir)
            if len(centdir) != sizeCentralDir:
                raise BadZipFile("Truncated central directory")
            centdir = struct.unpack(structCentralDir, centdir)
            if centdir[_CD_SIGNATURE] != stringCentralDir:
                raise BadZipFile("Bad magic number for central directory")
            if self.debug > 2:
                print(centdir)
            filename = fp.read(centdir[_CD_FILENAME_LENGTH])
            flags = centdir[5]
            if flags & 0x800:
                # UTF-8 file names extension
                filename = filename.decode('utf-8')
            else:
                # Historical ZIP filename encoding
                filename = filename.decode('cp437')
            # Create ZipInfo instance to store file information
            x = ZipInfo(filename)
            x.extra = fp.read(centdir[_CD_EXTRA_FIELD_LENGTH])
            x.comment = fp.read(centdir[_CD_COMMENT_LENGTH])
            x.header_offset = centdir[_CD_LOCAL_HEADER_OFFSET]
            (x.create_version, x.create_system, x.extract_version, x.reserved,
             x.flag_bits, x.compress_type, t, d,
             x.CRC, x.compress_size, x.file_size) = centdir[1:12]
            if x.extract_version > MAX_EXTRACT_VERSION:
                raise NotImplementedError("zip file version %.1f" %
                                          (x.extract_version / 10))
            x.volume, x.internal_attr, x.external_attr = centdir[15:18]
            # Convert date/time code to (year, month, day, hour, min, sec)
            x._raw_time = t
            x.date_time = ( (d>>9)+1980, (d>>5)&0xF, d&0x1F,
                            t>>11, (t>>5)&0x3F, (t&0x1F) * 2 )

            x._decodeExtra()
            x.header_offset = x.header_offset + concat
            x.isDirectory = x.is_dir()
            self.filelist.append(x)
            self.NameToInfo[x.filename] = x

            # update total bytes read from central directory
            total = (total + sizeCentralDir + centdir[_CD_FILENAME_LENGTH]
                     + centdir[_CD_EXTRA_FIELD_LENGTH]
                     + centdir[_CD_COMMENT_LENGTH])

            if self.debug > 2:
                print("total", total)

    def printdir(self, file=None):
        """Print a table of contents for the zip file."""
        print("%-46s %10s %12s %21s %15s" % ("File Name","Is Directory","Size", "Modified    ", "Comment"),
              file=file)
        for zinfo in self.filelist:
            date = "%d-%02d-%02d %02d:%02d:%02d" % zinfo.date_time[:6]
            str_comment = zinfo.comment.decode("utf-8")
            print("%-46s %10s %12d %30s %20s" % (zinfo.filename,zinfo.isDirectory, zinfo.file_size, date,str_comment),
                  file=file)



def main(args=None):
    description = "A Simple parser for reading zipfile contents"
    parser = argparse.ArgumentParser(description=description)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-l','--list',metavar='<zipfile>',help='Show list of all files and folders inside a zipfile')

    args = parser.parse_args(args)

    if args.list is not None:
        src = args.list

        with ZipFile(src, 'r') as zf:
            zf.printdir()


if __name__ =="__main__":
    main()

