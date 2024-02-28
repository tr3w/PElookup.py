#!/usr/bin/python
'''

PElookup.py

Find all ocurrences of a string in the Import and Export tables
of all the Portable Executable (PE) files under a specified directory.

Usage: PElookup.py [OPTION] "string_to_find" "directory_path"

OPTIONS:
-i Look in the Import table
-e Look in the Export table
-a Look in both the Import and Export tables

Example:
PElookup.py -a "VirtualProtect" "~/.wine/drive_c"


Written by Ruben V. Pina [tr3w]
@tr3w_
http://nzt-48.org

'''

import struct
import os
import sys

class PEace:
    
    def __init__(self, filename):
        
        try:
            self.f = open(filename, 'rb')
        except IOError:
            print("[!] Cannot open file: %s" % self.f.name)
        
        self.Magic = 0
        self._IMAGE_OPTIONAL_HEADER__size = 0
        self._IMAGE_FILE_HEADER__size = 0
        
        self._IMAGE_DOS_HEADER              = self.getDOSHeader()
        self._IMAGE_FILE_HEADER             = self.getPEHeader()
        self._IMAGE_OPTIONAL_HEADER         = self.getImageOptionalHeader()
        self._IMAGE_DATA_DIRECTORY          = self.getImageDataDirectory()
        self.Sections                       = self.getSections()
        self._IMAGE_IMPORT_MODULE_DIRECTORY = self.getImports()
        self._IMAGE_EXPORT_DIRECTORY        = self.getExports()

        
        
    def getDOSHeader(self):
        
        DOSHeader = self.f.read(0x40)
        
        if DOSHeader[:2] != b'MZ':
            print ("[!] Not a Portable Executable file. %s" % self.f.name)
            raise Exception
            
        
        return DOSHeader
        


    def getPEHeader(self):
        
        self.PEHeaderOffset = unpackL(self._IMAGE_DOS_HEADER[0x3c:])
        self.f.seek(self.PEHeaderOffset)
        
        NTSIGNATURE = self.f.read(0x4)
        if NTSIGNATURE != b'PE\0\0' and NTSIGNATURE != b'NE\0\0':
            print ("[!] Invalid PE header %s" % self.f.name)
            raise Exception
        
        position = self.f.tell()
        _IMAGE_FILE_HEADER = { 'Machine'                : unpackH(self.f.read(0x02)),
                               'NumberOfSections'       : unpackH(self.f.read(0x02)),
                               'TimeDateStamp'          : unpackL(self.f.read(0x04)), 
                               'PointerToSymbolTable'   : unpackL(self.f.read(0x04)),
                               'NumberOfSymbols'        : unpackL(self.f.read(0x04)),
                               'SizeOfOptionalHeader'   : unpackH(self.f.read(0x02)),
                               'Characteristics'        : unpackH(self.f.read(0x02))
                               }
        self._IMAGE_FILE_HEADER__size = 4 + (self.f.tell() - position)


       
        if _IMAGE_FILE_HEADER['Machine'] == b'\x4c\x01':
            pass
        elif _IMAGE_FILE_HEADER['Machine'] == b'\x00\x02':
            pass
        else:
            pass
        
        return _IMAGE_FILE_HEADER
            


    def getImageOptionalHeader(self):
        
        self.f.seek(self.PEHeaderOffset + self._IMAGE_FILE_HEADER__size)
        
        position = self.f.tell()
        _IMAGE_OPTIONAL_HEADER = {
            'Magic'                         : self.f.read(0x02),
            'MajorLinkerVersion'            : unpackB(self.f.read(0x01)),
            'MinorLinkerVersion'            : unpackB(self.f.read(0x01)),
            'SizeOfCode'                    : unpackL(self.f.read(0x04)),
            'SizeOfInitializedData'         : unpackL(self.f.read(0x04)),
            'SizeOfUninitializedData'       : unpackL(self.f.read(0x04)),
            'AddressOfEntryPoint'           : unpackL(self.f.read(0x04)),
            'BaseOfCode'                    : unpackL(self.f.read(0x04)),
            'BaseOfData'                    : unpackL(self.f.read(0x04)),
            'ImageBase'                     : unpackL(self.f.read(0x04)),
            'SectionAlignment'              : unpackL(self.f.read(0x04)),
            'FileAlignment'                 : unpackL(self.f.read(0x04)),
            'MajorOperatingSystemVersion'   : unpackH(self.f.read(0x02)),
            'MinorOperatingSystemVersion'   : unpackH(self.f.read(0x02)),
            'MajorImageVersion'             : unpackH(self.f.read(0x02)),
            'MinorImageVersion'             : unpackH(self.f.read(0x02)),
            'MajorSubsystemVersion'         : unpackH(self.f.read(0x02)),
            'MinorSubsystemVersion'         : unpackH(self.f.read(0x02)),
            'Reserverd1'                    : unpackL(self.f.read(0x04)),
            'SizeOfImage'                   : unpackL(self.f.read(0x04)),
            'SizeOfHeaders'                 : unpackL(self.f.read(0x04)),
            'CheckSum'                      : unpackL(self.f.read(0x04)),
            'Subsystem'                     : unpackH(self.f.read(0x02)),
            'DllCharacteristics'            : unpackH(self.f.read(0x02)),
            'SizeOfStackReserve'            : unpackL(self.f.read(0x04)),
            'SizeOfStackCommit'             : unpackL(self.f.read(0x04)),
            'SizeOfHeapReserve'             : unpackL(self.f.read(0x04)),
            'SizeOfHeapCommit'              : unpackL(self.f.read(0x04)),
            'LoaderFlags'                   : unpackL(self.f.read(0x04)),
            'NumberOfRvaAndSizes'           : unpackL(self.f.read(0x04))
        }
        
        if _IMAGE_OPTIONAL_HEADER['Magic'] == b'\x0b\x01':
            self.Magic = 4
        elif _IMAGE_OPTIONAL_HEADER['Magic']  == b'\x0b\x02':
            self.Magic = 8
        
        self._IMAGE_OPTIONAL_HEADER__size = self.f.tell() - position

        return _IMAGE_OPTIONAL_HEADER




    def getImageDataDirectory(self):
        
        # ImageDataDirectory (the last entry of the OptionalHeader) has 16 entries of 8 bytes each (0x80)        
        
        _IMAGE_DATA_DIRECTORY = []
        self.f.seek(self.PEHeaderOffset + self._IMAGE_FILE_HEADER__size + self._IMAGE_OPTIONAL_HEADER__size)

        for d in range(0, 16):
            _IMAGE_DATA_DIRECTORY.append({ 'VirtualAddress' : unpackL(self.f.read(0x04)),
                                           'Size'   : unpackL(self.f.read(0x04)) })
        self._IMAGE_DATA_DIRECTORY__size = 0x08 * 0x10
 
        return _IMAGE_DATA_DIRECTORY
    


    def getSections(self):
        
        NumberOfSections = self._IMAGE_FILE_HEADER['NumberOfSections']
        Sections = []
        f = self.f
        f.seek(self.PEHeaderOffset + self._IMAGE_FILE_HEADER__size + self._IMAGE_OPTIONAL_HEADER__size + self._IMAGE_DATA_DIRECTORY__size)
        for i in range(0, NumberOfSections):
            Sections.append({'Name'                : f.read(0x8),
                             'PhysicalAddress'     : unpackL(f.read(0x4)),
                             'VirtualAddress'      : unpackL(f.read(0x4)),
                             'SizeOfRawData'       : unpackL(f.read(0x4)),
                             'PointerToRawData'    : unpackL(f.read(0x4)),
                             'PointerToRelocations': unpackL(f.read(0x4)),
                             'PointerToLinenumbers': unpackL(f.read(0x4)),
                             'NumberOfRelocations' : unpackH(f.read(0x2)),
                             'NumberOfLinenumbers' : unpackH(f.read(0x2)),
                             'Characteristics'     : unpackL(f.read(0x4))
                             })
        return Sections
    


    def getSectionByName(self, Name):
        for section in self.Sections:
            if bytes(Name, encoding='UTF-8') in section['Name']:
                return section
        
        return 0
    


    def getExports(self):
        
        f = self.f
        ExportSection = self.getSectionByName('.edata')
        if not ExportSection: return 0
        ExportOffset = ExportSection['PointerToRawData']
        ImageExportOffset = self._IMAGE_DATA_DIRECTORY[0]['VirtualAddress']
        ExportSize = ExportSection['SizeOfRawData']

        f.seek(ExportOffset)
        ImageExportDirectory = f.read(ExportSize)
        
        NumberOfFunctions = unpackL(ImageExportDirectory[0x14:0x18])
        NumberOfNames = unpackL(ImageExportDirectory[0x18:0x1c])

        AddressOfFunctions = unpackL(ImageExportDirectory[0x1c:0x20]) - ImageExportOffset + ExportOffset
        AddressOfNames = unpackL(ImageExportDirectory[0x20:0x24]) - ImageExportOffset + ExportOffset
        
        f.seek(AddressOfNames)
        ExportNamePointers = f.read(NumberOfNames * 4)
        
        ExportNamesPointers = [unpackL(ExportNamePointers[i:i+4]) - ImageExportOffset + ExportOffset for i in range(0, len(ExportNamePointers), 4)]
        ExportNamePointers = []
        i = 0
        for pointer in ExportNamesPointers:
            ExportNamePointers.append(self.readNTBS(pointer))
        
        return ExportNamePointers
        

    def getImports(self):

        ImportSection = self.getSectionByName('.idata')
        if not ImportSection: return 0
        ImportOffset = ImportSection['PointerToRawData']
        ImportSize = ImportSection['SizeOfRawData']
        ImageImportDirectory = []
        
        f = self.f
        f.seek(ImportOffset)
        for i in range(0x14, ImportSize, 0x14):
            ImageImportDirectory.append(f.read(0x14))
        
        ImportModules = []
        for module in ImageImportDirectory:
            if module == bytes('\x00' * 0x14, encoding='UTF-8'): # extra validation cuz sometimes ImportSize says another thing
                break
            module_name = unpackL(module[0xc:0x10]) + ImportOffset - self._IMAGE_DATA_DIRECTORY[1]['VirtualAddress']  # - ImageImportOffset + ImportOffset
            FirstThunk = unpackL(module[:0x4])
            offset_to_pointers = FirstThunk + ImportOffset - self._IMAGE_DATA_DIRECTORY[1]['VirtualAddress']

            pointers = []
            f.seek(offset_to_pointers)
            while 1:
                pointer = unpackL(f.read(self.Magic))
                if not pointer:
                    break
                pointers.append(pointer + ImportOffset - self._IMAGE_DATA_DIRECTORY[1]['VirtualAddress'])
            
            for p in pointers:
                ImportModules.append("%s : %s" % (self.readNTBS(module_name), self.readNTBS(p+2)))
        
        return ImportModules
    
    
    # read byte string until NULL byte 
    def readNTBS(self, p):
        s = ''
        self.f.seek(p)
        while 1:
            s += str(self.f.read(1), encoding='UTF-8')
            if s[-1] == "\x00":
                return s[:-1]
    


def unpackL(s):
    return struct.unpack("<L", s)[0]

def unpackH(s):
    return struct.unpack("<H", s)[0]

def unpackB(s):
    return struct.unpack("<B", s)[0]


def usage():
    print("Usage: %s [0|1|2] \"string_to_search\" [\"directory\" | \"filename\"]" % sys.argv[0])
    print("\t -e look for exports")
    print("\t -i looks for imports")
    print("\t -a looks for both exports and imports")
    print("\t string_to_search: string to search in export and import directories")
    print("\t filename: to scan, if directory is given all containing files will be scanned.")
    
    sys.exit(-1)



def start(argument, search_string, path):
    pe_extensions = ['.cpl', '.exe', '.dll', '.ocx', '.sys', '.scr', '.drv', '.efi', '.fon']
    pe = []
    
    try:
        os.listdir(path)
        for root, directories, files in os.walk(path):
            for f in files:
                pe_path = os.path.join(root, f)
                if os.path.splitext(f)[1].lower() in pe_extensions:
                    pe.append(pe_path)
    except:
        pe.append(path)
    
    for p in pe:
        try:
            PE = PEace(p)
            exports = []
            imports = []
            # print("\n[*] Scanning: %s" % p)
            if argument == '-e' or argument == '-a':
                for Export in PE._IMAGE_EXPORT_DIRECTORY or []:
                    if search_string in Export:
                        exports.append("\t[+] Export found: %s" % Export)
            if argument == '-i' or argument == '-a':
                for Import in PE._IMAGE_IMPORT_MODULE_DIRECTORY or []:
                    if search_string in Import:
                        imports.append("\t[+] Import found: %s" % Import)
            if len(imports) or len(exports):
                print("\n[*] Scanned: %s" % p)
                for i in imports:
                    print(i)
                for e in exports:
                    print(e)
                    
        except Exception:
            continue
    
    print("\n[!] Done.")


if len(sys.argv) != 4:
    usage()
searchExports = searchImports = 0
if not (sys.argv[1] == '-i' or sys.argv[1] == '-e' or sys.argv[1] == '-a'):
    print("[x] Invalid argument.")
    usage()

argument = sys.argv[1]
search_string = sys.argv[2]
search_directory = sys.argv[3]

start(argument, search_string, search_directory)