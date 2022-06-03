# ZipfileChallenge

## Problem
Implement a command-line parser program to list all files and folders inside the provided zip file. The parser should
print the following fields for each file and folder, one file per line:
- Name
- Whether the item is a folder
- Uncompressed Size
- Modified date
- Comment

The parser should be extensible for future additions, such that another developer could easily add support for encryption
and file content extraction, or add other fields present in the same data structures to be parsed and output. You do not
need to support the following in your parser: encryption; file content extraction; ZIP64.

Do not use an existing built-in or third-party library, such as Python’s zipfile module or Rust’s zip crate.

Here are two resources for Zip file format documentation:
- https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
- https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip-printable.html

There are numerous other resources on the Internet documenting the format, as well.
## Code_sample
```
$ ./zip_parser exercise.zip
folder True 0 2022-05-19T10:51:38
folder/folder True 0 2022-05-19T10:51:18 A nested folder
folder/folder/test.txt False 125 2022-05-19T10:56:30
...
$
```

## Problem solving

I took some references from the Python zipfile's code sample from this https://github.com/python/cpython/blob/3.10/Lib/zipfile.py 

zip file specifications is used to read the files one by one and based on the central directory each file is read and decoded to pront 

## Solution Usage 
```
exerciseOwn.py -l work_sample_exercise.zip
```
```
usage: exerciseOwn.py [-h] -l <zipfile>

A Simple parser for reading zipfile contents

optional arguments:
  -h, --help            show this help message and exit
  -l <zipfile>, --list <zipfile>
                        Show list of all files and folders inside a zipfile
                        
```
## Some notes about Zip file 
- A ZIP file MUST contain an "end of central directory record". A ZIP file containing only an "end of central directory record" is considered an empty ZIP file.

