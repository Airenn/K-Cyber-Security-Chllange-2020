import pefile
import struct
import binascii
import sys
import time

#pe = pefile.PE('C:\\Program Files (x86)\\HNC\\Office 2018\\HOffice100\\Bin\\hwp.exe')
pe = pefile.PE('C:\\Users\\USER\\Desktop\\프로그램\\Tool\\upx\\5bd3e31b75686582925a42028a137ac9')

def print_info (data_list) :
    for data in data_list :
        print(data[0].ljust(30), str(data[1]).ljust(40), data[2].ljust(10), data[3].ljust(10), data[4].ljust(10))
def ord2hex(string) : # 10진수 hex -> b'Value'
    if(type(string) == bytes):
        return hex2ascii(string)
    else:
        test = len(hex(string))
        #print(test ,hex(string), struct.pack('<Q', int(string)), len(struct.pack('<L', int(string))))
        return struct.pack('<L', int(string))

def hex2ascii(value) : # bytes -> ascii
    if(type(value) == bytes):
        return (str(binascii.hexlify(value), 'ascii')).upper() # bytes -> ascii

    else:
        return value
def header_info (header_name ,key, elms) :
    header_list = []

    if (header_name != ""): 
        print(header_name)
        print("-" * 30)
        header_list.append(["Name","Raw Data","Value","Hex","Mean"])

    for name, digit in zip(key, elms):
        b_value = (ord2hex(digit))
        raw_data = hex2ascii(b_value)
        try:
            value = b_value.decode('ASCII')
        except:
            value = ""
        if(type(digit) == int):
            hex_value = hex(digit)
        else:
            hex_value = ""           
        header_list.append([name[0], raw_data, value, hex_value, "DOS Signature"])    

    print_info(header_list)
    if (header_name != ""): 
        print("-" * 30)
"""
def nt_header_info (pe) :
    print("-" * 30)
    print("[NT header]에서 필요한 정보\n")
    nt_header_list = []
    nt_header_list.append(["Name","Raw Data","Value","Hex", "Mean"])
    nt_header_list.append(["Signature", hex2ascii(ord2hex(pe.NT_HEADERS.Signature)),(ord2hex(pe.NT_HEADERS.Signature)).decode("utf8"),hex(pe.NT_HEADERS.Signature), "NF Signature"])

    for name, digit in zip(pe.FILE_HEADER.__keys__, pe.FILE_HEADER.__unpacked_data_elms__):
        b_value = (ord2hex(digit))
        raw_data = hex2ascii(b_value)
        try:
            value = b_value.decode('utf8')

        except:
            value = " "
        if(type(digit) == int):
            hex_value = hex(digit)
        else:
            hex_value = " "           
        nt_header_list.append([name[0], raw_data , value, hex_value,"DOS Signature"])      

    for name, digit in zip(pe.OPTIONAL_HEADER.__keys__, pe.OPTIONAL_HEADER.__unpacked_data_elms__):
        b_value = (ord2hex(digit))
        raw_data = hex2ascii(b_value)
        try:
            value = b_value.decode('utf8')

        except:
            value = " "
        if(type(digit) == int):
            hex_value = hex(digit)
        else:
            hex_value = " "           
        nt_header_list.append([name[0], raw_data , value, hex_value,"DOS Signature"])
    print_info(nt_header_list)
"""
"""
print(hex(pe.DOS_HEADER.e_cblp))
"""

#print(pe.print_info())
print(pe.get_data(45152))
#header_info("dos_header_info" ,pe.DOS_HEADER.__keys__, pe.DOS_HEADER.__unpacked_data_elms__)
#header_info("NT_header_info" ,pe.NT_HEADERS.__keys__, pe.NT_HEADERS.__unpacked_data_elms__)
#header_info("" ,pe.FILE_HEADER.__keys__, pe.FILE_HEADER.__unpacked_data_elms__)
#header_info("" ,pe.OPTIONAL_HEADER.__keys__, pe.OPTIONAL_HEADER.__unpacked_data_elms__)
#print("*" * 50)

#for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
#    print(entry.name + "\n|\n|---- Size : " + str(entry.Size) , "0x" + str(hex(entry.Size)[2:]).rjust(8, "0")  + "\n|\n|---- VirutalAddress : " + hex(entry.VirtualAddress) + '\n')    
#print("*" * 50)
#print(pe.sections)
#f = open('test.txt', mode='wt', encoding='utf-8')
#start = time.time()
#for section in pe.sections:
#    section_dict = section.dump_dict()
#    section_test = section.get_data()
#    print(section.Name)
    #test = section_test.find(b'PAPADDING')
    #test2 = section_test.find(b'\x50\x41\x50\x41\x44\x44\x49\x4E\x47')
    #if (section.Name == b'.rsrc\x00\x00\x00'):
    #   f.write(str(section_test))
#    print(str(section.Name, 'ascii'), section.get_entropy(), section_test)
#print("time :", time.time() - start)


print( [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries])
print(pefile.RESOURCE_TYPE['RT_ICON'])
strings = list()
#pe.DIRECTORY_ENTRY_RESOURCE.entries[0].name.pe
rt_string_idx = [
  entry.id for entry in 
  pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_ICON'])
print(rt_string_idx)

rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]

for entry in rt_string_directory.directory.entries:
    
  # Get the RVA of the string data and
  # size of the string data
  #
  data_rva = entry.directory.entries[0].data.struct.OffsetToData
  size = entry.directory.entries[0].data.struct.Size
  print('Directory entry at RVA', hex(data_rva), 'of size', hex(size))

  # Retrieve the actual data and start processing the strings
  #
  data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
  print(data)
  offset = 0
  while True:
    # Exit once there's no more data to read
    if offset>=size:
      break
    # Fetch the length of the unicode string
    #
    ustr_length = pe.get_word_from_data(data[offset:offset+2], 0)
    offset += 2

    # If the string is empty, skip it
    if ustr_length==0:
      continue

    # Get the Unicode string
    #
    ustr = pe.get_string_u_at_rva(data_rva+offset, max_length=ustr_length)
    offset += ustr_length*2
    strings.append(ustr)
    print ('String of length', ustr_length, 'at offset', offset)