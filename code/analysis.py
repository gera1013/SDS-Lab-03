from os import listdir
from os.path import isfile, join

import pefile
import numpy as np
import pandas as pd

files = []
entries = []

		
with open('files.txt', 'r') as f:
	files = f.readlines()

for file in files:
	entry = []
	
	pe = pefile.PE(file.replace('\n', ''))
	
	## DOS HEADER
	entry.append(pe.DOS_HEADER.e_lfanew)
	# entry.append(pe.DOS_HEADER.e_magic)
	
	
	## NT HEADERS
	#entry.append(pe.NT_HEADERS.Signature)
	
	
	## FILE_HEADER
	entry.append(pe.FILE_HEADER.Characteristics)
	#entry.append(pe.FILE_HEADER.Machine)
	#entry.append(pe.FILE_HEADER.NumberOfSections)
	
	
	## OPTIONAL HEADER
	entry.append(pe.OPTIONAL_HEADER.SizeOfImage)
	entry.append(pe.OPTIONAL_HEADER.ImageBase)
	#entry.append(pe.OPTIONAL_HEADER.Magic)
	#entry.append(pe.OPTIONAL_HEADER.SectionAlignment)
	#entry.append(pe.OPTIONAL_HEADER.FileAlignment)
	#entry.append(pe.OPTIONAL_HEADER.DllCharacteristics)

	for en in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
		if en.name in [
			'IMAGE_DIRECTORY_ENTRY_EXPORT',
			'IMAGE_DIRECTORY_ENTRY_IMPORT',
			'IMAGE_DIRECTORY_ENTRY_RESOURCE'
		]:
			entry.append(en.Size)
			entry.append(en.VirtualAddress)
			
	## SECTIONS HEADER
	names = []
	for section in pe.sections:
		name = section.Name.decode().rstrip('\x00')
		
		names.append(name)

	if '.rsrc' in names:
		entry.append(1)
	else:
		entry.append(0)
		
	if 'UPX0' in names:
		entry.append(1)
	else:
		entry.append(0)
		
	if 'UPX1' in names:
		entry.append(1)
	else:
		entry.append(0)
		
	if 'UPX2' in names:
		entry.append(1)
	else:
		entry.append(0)
		
	if '.text' in names:
		entry.append(1)
	else:
		entry.append(0)
		
	if '.rdata' in names:
		entry.append(1)
	else:
		entry.append(0)
	
	if '.data' in names:
		entry.append(1)
	else:
		entry.append(0)
		

	## IMPORTED SYMBOLS
	no_imported_symbols = 0
	no_exported_symbols = 0
	
	for en in pe.DIRECTORY_ENTRY_IMPORT:
		for imp in en.imports:
			no_imported_symbols += 1
			
	entry.append(no_imported_symbols)
	
	## EXPORTED SYMBOLS
	try:
		for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
			no_exported_symbols += 1
	except:		
		no_exported_symbols = no_exported_symbols
	
	entry.append(no_exported_symbols)
	
	# transform a numpy array
	np_entry = np.array(entry)
	
	entries.append(np_entry)
	
np_entries = np.array(entries)

# print(np_entries)

features = pd.DataFrame(
	data=entries,
	columns=[
		'e_lfanew',
		'characteristics',
		'size_of_image',
		'image_base',
		'IDEE_size',
		'IDEE_virtual_address',
		'IDEI_size',
		'IDEI_virtual_address',
		'IDER_size',
		'IDER_virtual_address',
		'.rsrc',
		'UPX0',
		'UPX1',
		'UPX2',
		'.text',
		'.rdata',
		'.data',
		'no_imported_symbols',
		'no_exported_symbols'
	]
)

features.to_csv("features.csv")
