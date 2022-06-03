import argparse
import struct
import io
import os 
import sys

def test():
    structCentralDir = b"<4s4B4HL2L5H2L"
    stringCentralDir = b"PK\001\002"
    sizeCentralDir = struct.calcsize(structCentralDir)
    print(sizeCentralDir)
    print(structCentralDir.decode('utf-8'))
class ZipFile:
    # fp = None
    def __init__(self,file,mode='rb'):
        while True:
            try:
                self.fp = io.open(file,mode)
            except OSError:
                raise
            break
        self._GetFileContents()
    def __enter__(self):
        return self
    
    def __exit__(self, type, value, traceback):
        self.fp.close()

    def _GetFileContents(self):
        fp = self.fp
        # Calculate the file size using seek and tell 
        # Moving the file handle to the end of the file 
        fp.seek(0,2)
        # calculate the bytes seeked 
        filesize = fp.tell()
        # print(filesize)
        
        '''
        
        Get the End of Central directory comments 
        According to 4.3.16 End of central directory record size is 22bytes. This should be the end of the data if no archive comment is found 

        '''
       
        try:
            fp.seek(-22,2)
        except OSError:
            return None
        
        data = fp.read()
        # print(data)

        '''
            Check for the correct zip file signature and unpack the data structure 
        	The signature of end of central directory record. This is always '\x50\x4b\x05\x06'.
            0 - end of central dir signature    4 bytes  (0x06054b50)
            1 - number of this disk             2 bytes
            2 - number of the disk with the
            start of the central directory  2 bytes
            3 - total number of entries in the
            central directory on this disk  2 bytes
            4 - total number of entries in
            the central directory           2 bytes
            5 - size of the central directory   4 bytes
            6 - offset of start of central
            directory with respect to
            the starting disk number        4 bytes
            7 - .ZIP file comment length        2 bytes
            8 - .ZIP file comment       (variable size)
        '''
        if (len(data) == 22 and data[0:4] == b"\x50\x4b\x05\x06" and data[-2:] == b"\000\000"):
            centralDirectoryRecord = list(struct.unpack(b"<4s4H2LH",data))

            size_cd = centralDirectoryRecord[5]
            offset_cd = centralDirectoryRecord[6]

        else:
            print("Zip file issue")

        fp.seek(offset_cd,0)
        data = fp.read(size_cd)
        fp = io.BytesIO(data)

        '''
        Start reading the central directory structure 
        until all files are read
        4.3.12  Central directory structure:

        [central directory header 1]
        .
        .
        . 
        [central directory header n]
        [digital signature] 

        File header:

            0 - central file header signature   4 bytes  (0x02014b50)
            1 - version made by                 2 bytes
            2 - version create system 
            3 - version needed to extract       2 bytes
            4 - extract system 
            5 - general purpose bit flag        2 bytes
            6 - compression method              2 bytes
            7 - last mod file time              2 bytes
            8 - last mod file date              2 bytes
            9 - crc-32                          4 bytes
            10 - compressed size                 4 bytes
            11 - uncompressed size               4 bytes
            12 - file name length                2 bytes
            13 - extra field length              2 bytes
            14 - file comment length             2 bytes
            15 - disk number start               2 bytes
            16 - internal file attributes        2 bytes
            17 - external file attributes        4 bytes
            18 - relative offset of local header 4 bytes

            file name (variable size)
            extra field (variable size)
            file comment (variable size)
        '''
        print("%-46s %10s %12s %21s %15s" % ("File Name","Is Directory","Size", "Modified    ", "Comment"))
        total = 0
        while total < size_cd:
            centdir = fp.read(46)
            # print(centdir)
            if len(centdir) != 46:
                print("zip file truncated")
            centdir = struct.unpack(b"<4s4B4HL2L5H2L",centdir)
            # print(centdir)
            # print(centdir)
            if centdir[0] != b"PK\001\002":
                print("bad bad")
            else:
                
                # Get the filename 
                filename = fp.read(centdir[12])
                filename = filename.decode('utf-8')
                # Find if it''s directory 
                isDirectory = filename[-1] == '/'
                # Find the Size
                uncompressedSize = centdir[11]
                # Find Modified Date
                '''
                4.4.6 date and time fields: (2 bytes each)

                The date and time are encoded in standard MS-DOS format.
                If input came from standard input, the date and time are
                those at which compression was started for this data. 
                If encrypting the central directory and general purpose bit 
                flag 13 is set indicating masking, the value stored in the 
                Local Header will be zero. MS-DOS time format is different
                from more commonly used computer time formats such as 
                UTC. For example, MS-DOS uses year values relative to 1980
                and 2 second precision.

                The MS-DOS date. The date is a packed value with the following format.
                    Bits    Description
                    0-4     Day of the month (1–31)
                    5-8     Month (1 = January, 2 = February, and so on)
                    9-15    Year offset from 1980 (add 1980 to get actual year)

                The MS-DOS time. The time is a packed value with the following format.
                    Bits    Description
                    0-4     Second divided by 2
                    5-10    Minute (0–59)
                    11-15    Hour (0–23 on a 24-hour clock)
                '''
                lmt = centdir[7]
                lmd = centdir[8]
                date_time = ( (lmd>>9)+1980, (lmd>>5)&0xF, lmd&0x1F,
                                lmt>>11, (lmt>>5)&0x3F, (lmt&0x1F) * 2 )
                formatted_date = "%d-%02d-%02d %02d:%02d:%02d" % date_time[:6]
                # Read Extras 
                extra = fp.read(centdir[13])
                # Get the comment if there are any 
                fileComment = fp.read(centdir[14]).decode('utf-8')
                print("%-46s %10s %12d %30s %20s" % (filename,isDirectory, uncompressedSize,formatted_date,fileComment))
                
                total = (total + int(46) + centdir[12] + centdir[13] + centdir[14])
                # print(total)

def main(args=None):
    description = "A Simple parser for reading zipfile contents"
    parser = argparse.ArgumentParser(description=description)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-l','--list',metavar='<zipfile>',help='Show list of all files and folders inside a zipfile')

    args = parser.parse_args(args)

    if args.list is not None:
        src = args.list
        with ZipFile(src) as zf:
            print("Parser completed reading all files")

if __name__ =="__main__":
    main()