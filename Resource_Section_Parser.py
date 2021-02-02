
import os
import re
import sys
import time
import glob
import pefile
import struct
import binascii
import itertools
import pandas as pd
import numpy as np



pe_list = list()
resource_list = [0]*10000
mz_list = [0]*10000
mz_list2 = [0]*10000
Train = pd.read_csv('C:\\Users\\USER\\Desktop\\박해민\\공부\\ML\\2. AI Malware\\Train\\label.csv') 
total_time = 0
total_time2 = 0

# 리소스에 MZ, Resource Type 개수? PK, 
# 폴더 내 모든 파일 -> 리스트 -> PeFile 읽기
path_dir = 'C://Users//USER//Desktop//박해민//공부//ML//2. AI Malware//Train//train_set//*'
file_list = glob.glob(path_dir)
regex = re.compile("[a-z0-9]{64}")


for num, file in enumerate(file_list):
  pe = pefile.PE(file)
  print(num+1, file)
  file_name = regex.findall(file)
  index = Train[Train['Hash'] == file_name[0]].index[0]

  # 리소스 검사 1
  start = time.time()
  try:
    IMAGE_RESOURCE_DIRECTORY_list = [entry for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries] # 리소스 섹션 검사

  except:
    resource_list[index] = 0 # 리소스 섹션 없음
    continue

  resource_list[index] = 1 # 리소스 섹션 있음

  IMAGE_RESOURCE_DIRECTORY_ENTRY_list = list(itertools.chain.from_iterable([entry.directory.entries for entry in IMAGE_RESOURCE_DIRECTORY_list]))
  IMAGE_RESOURCE_DIRECTORY_ENTRY_list_ = list(itertools.chain.from_iterable([entry.directory.entries for entry in IMAGE_RESOURCE_DIRECTORY_ENTRY_list]))
  entry_list = [pe.get_memory_mapped_image()[entry.data.struct.OffsetToData:entry.data.struct.OffsetToData+entry.data.struct.Size] for entry in IMAGE_RESOURCE_DIRECTORY_ENTRY_list_]
  start = time.time()
  mz_list[index] = next((1 for entry in entry_list if entry[:4].find(b'MZ') != -1), 0) # 리소스에 MZ 확인
  total_time += time.time() - start
  print("time1 :", time.time() - start)
  start = time.time()
  # 리소스에 MZ 확인
  for entry in entry_list:
    #print(entry[:4])
    if entry[:4].find(b'MZ') != -1:
      mz_list2[index] = 1
      total_time2 += time.time() - start
      #print("time2 :", time.time() - start)
      break
    total_time2 += time.time() - start
    
  if num == 100:
    break

Train['resource_section'] = resource_list
Train['resource_in_MZ'] = mz_list
Train.to_csv("Test.csv", index=False)
print(Train[0:100])
# 리소스 검사 2
"""
  start = time.time()
  for IMAGE_RESOURCE_DIRECTORY in pe.DIRECTORY_ENTRY_RESOURCE.entries:
      for i ,IMAGE_RESOURCE_DIRECTORY_ENTRY in enumerate(IMAGE_RESOURCE_DIRECTORY.directory.entries):
          for entry in IMAGE_RESOURCE_DIRECTORY_ENTRY.directory.entries:
              data_rva = entry.data.struct.OffsetToData
              size = entry.data.struct.Size
              string = (pe.get_memory_mapped_image()[data_rva:data_rva+size])
              print(string)
              #test = string[:4].find(b'\x4D\x5A') # 4바이트내 4D5A(MZ) 검사
              
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
              
  total_time3 += (time.time() - start)              
  print(num, "time3 :", time.time() - start)
  print("total_time1 = ", total_time1, "total_time3 = ", total_time3) 
"""
# 종료
print("end")