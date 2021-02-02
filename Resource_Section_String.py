import pefile
import struct
import binascii
import sys
import time
import itertools

pe = pefile.PE('C:\\Program Files (x86)\\HNC\\Office 2018\\HOffice100\\Bin\\hwp.exe')
#pe = pefile.PE('C:\\Users\\USER\\Desktop\\프로그램\\Tool\\upx\\5bd3e31b75686582925a42028a137ac9')
strings = list()

start = time.time()
IMAGE_RESOURCE_DIRECTORY_list = [entry for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries]
IMAGE_RESOURCE_DIRECTORY_ENTRY_list = list(itertools.chain.from_iterable([entry.directory.entries for entry in IMAGE_RESOURCE_DIRECTORY_list]))
entry = [pe.get_memory_mapped_image()[entry.directory.entries[0].data.struct.OffsetToData:entry.directory.entries[0].data.struct.OffsetToData+entry.directory.entries[0].data.struct.Size] for entry in IMAGE_RESOURCE_DIRECTORY_ENTRY_list]
print(entry[0])

print("time1 :", time.time() - start)
start = time.time()
IMAGE_RESOURCE_DIRECTORY_ENTRY_list2 = list(itertools.chain.from_iterable([[pe.get_memory_mapped_image()[entry.directory.entries[0].data.struct.OffsetToData:entry.directory.entries[0].data.struct.OffsetToData+entry.directory.entries[0].data.struct.Size] for entry in entry_list.directory.entries] for entry_list in pe.DIRECTORY_ENTRY_RESOURCE.entries]))
print("time2 :", time.time() - start)
#entry.directory.entries for entry.directory.entries in entry_list
#entry = [pe.get_memory_mapped_image()[entry.directory.entries[0].data.struct.OffsetToData:entry.directory.entries[0].data.struct.OffsetToData+entry.directory.entries[0].data.struct.Size] for entry in IMAGE_RESOURCE_DIRECTORY_ENTRY_list]
#print("time :", time.time() - start)

start = time.time()
for IMAGE_RESOURCE_DIRECTORY in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    for i ,IMAGE_RESOURCE_DIRECTORY_ENTRY in enumerate(IMAGE_RESOURCE_DIRECTORY.directory.entries):
        for entry in IMAGE_RESOURCE_DIRECTORY_ENTRY.directory.entries:
            data_rva = entry.data.struct.OffsetToData
            size = entry.data.struct.Size
            string = (pe.get_memory_mapped_image()[data_rva:data_rva+size])[:100].find(b'\xD2')
            test = string[:4].find(b'\x5A\x90')
            """
            start = 0
            end = 16
            while True:
                
                print(pefile.RESOURCE_TYPE[IMAGE_RESOURCE_DIRECTORY.id],i ,string[start:end],end='\n')

                if len(string[end:]) < 17:
                    print(pefile.RESOURCE_TYPE[IMAGE_RESOURCE_DIRECTORY.id],i,string[end:])
                    break
                else:
                    start = end
                    end += 16
            """
print("time3 :", time.time() - start)


"""
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
"""