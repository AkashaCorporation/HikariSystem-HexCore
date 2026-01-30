/*---------------------------------------------------------------------------------------------
 *  HexCore Hex Viewer - Structure Templates
 *  Predefined structure templates for binary parsing
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

export interface TemplateField {
	name: string;
	type: 'uint8' | 'uint16' | 'uint32' | 'uint64' | 'ascii' | 'unicode' | 'bytes';
	length?: number;
	description?: string;
}

export interface StructureTemplate {
	name: string;
	description: string;
	size: number;
	fields: TemplateField[];
}

export const STRUCTURE_TEMPLATES: StructureTemplate[] = [
	{
		name: 'DOS_Header',
		description: 'DOS MZ Header',
		size: 64,
		fields: [
			{ name: 'e_magic', type: 'uint16', description: 'Magic number (MZ)' },
			{ name: 'e_cblp', type: 'uint16', description: 'Bytes on last page' },
			{ name: 'e_cp', type: 'uint16', description: 'Pages in file' },
			{ name: 'e_crlc', type: 'uint16', description: 'Relocations' },
			{ name: 'e_cparhdr', type: 'uint16', description: 'Header paragraphs' },
			{ name: 'e_minalloc', type: 'uint16', description: 'Min extra paragraphs' },
			{ name: 'e_maxalloc', type: 'uint16', description: 'Max extra paragraphs' },
			{ name: 'e_ss', type: 'uint16', description: 'Initial SS' },
			{ name: 'e_sp', type: 'uint16', description: 'Initial SP' },
			{ name: 'e_csum', type: 'uint16', description: 'Checksum' },
			{ name: 'e_ip', type: 'uint16', description: 'Initial IP' },
			{ name: 'e_cs', type: 'uint16', description: 'Initial CS' },
			{ name: 'e_lfarlc', type: 'uint16', description: 'Reloc table offset' },
			{ name: 'e_ovno', type: 'uint16', description: 'Overlay number' },
			{ name: 'e_res', type: 'bytes', length: 8, description: 'Reserved' },
			{ name: 'e_oemid', type: 'uint16', description: 'OEM identifier' },
			{ name: 'e_oeminfo', type: 'uint16', description: 'OEM info' },
			{ name: 'e_res2', type: 'bytes', length: 20, description: 'Reserved 2' },
			{ name: 'e_lfanew', type: 'uint32', description: 'PE header offset' }
		]
	},
	{
		name: 'PE_Signature',
		description: 'PE Signature',
		size: 4,
		fields: [
			{ name: 'Signature', type: 'ascii', length: 4, description: 'PE\\0\\0' }
		]
	},
	{
		name: 'COFF_Header',
		description: 'COFF File Header',
		size: 20,
		fields: [
			{ name: 'Machine', type: 'uint16', description: 'Target machine' },
			{ name: 'NumberOfSections', type: 'uint16', description: 'Section count' },
			{ name: 'TimeDateStamp', type: 'uint32', description: 'Timestamp' },
			{ name: 'PointerToSymbolTable', type: 'uint32', description: 'Symbol table offset' },
			{ name: 'NumberOfSymbols', type: 'uint32', description: 'Symbol count' },
			{ name: 'SizeOfOptionalHeader', type: 'uint16', description: 'Optional header size' },
			{ name: 'Characteristics', type: 'uint16', description: 'File characteristics' }
		]
	},
	{
		name: 'Optional_Header32',
		description: 'PE32 Optional Header',
		size: 224,
		fields: [
			{ name: 'Magic', type: 'uint16', description: 'Magic number (0x10B)' },
			{ name: 'MajorLinkerVersion', type: 'uint8', description: 'Linker major' },
			{ name: 'MinorLinkerVersion', type: 'uint8', description: 'Linker minor' },
			{ name: 'SizeOfCode', type: 'uint32', description: 'Code section size' },
			{ name: 'SizeOfInitializedData', type: 'uint32', description: 'Initialized data size' },
			{ name: 'SizeOfUninitializedData', type: 'uint32', description: 'Uninitialized data size' },
			{ name: 'AddressOfEntryPoint', type: 'uint32', description: 'Entry point RVA' },
			{ name: 'BaseOfCode', type: 'uint32', description: 'Code base RVA' },
			{ name: 'BaseOfData', type: 'uint32', description: 'Data base RVA' },
			{ name: 'ImageBase', type: 'uint32', description: 'Image base address' },
			{ name: 'SectionAlignment', type: 'uint32', description: 'Section alignment' },
			{ name: 'FileAlignment', type: 'uint32', description: 'File alignment' },
			{ name: 'MajorOperatingSystemVersion', type: 'uint16', description: 'OS major version' },
			{ name: 'MinorOperatingSystemVersion', type: 'uint16', description: 'OS minor version' },
			{ name: 'MajorImageVersion', type: 'uint16', description: 'Image major version' },
			{ name: 'MinorImageVersion', type: 'uint16', description: 'Image minor version' },
			{ name: 'MajorSubsystemVersion', type: 'uint16', description: 'Subsystem major' },
			{ name: 'MinorSubsystemVersion', type: 'uint16', description: 'Subsystem minor' },
			{ name: 'Win32VersionValue', type: 'uint32', description: 'Reserved' },
			{ name: 'SizeOfImage', type: 'uint32', description: 'Image size' },
			{ name: 'SizeOfHeaders', type: 'uint32', description: 'Headers size' },
			{ name: 'CheckSum', type: 'uint32', description: 'Checksum' },
			{ name: 'Subsystem', type: 'uint16', description: 'Subsystem' },
			{ name: 'DllCharacteristics', type: 'uint16', description: 'DLL characteristics' },
			{ name: 'SizeOfStackReserve', type: 'uint32', description: 'Stack reserve size' },
			{ name: 'SizeOfStackCommit', type: 'uint32', description: 'Stack commit size' },
			{ name: 'SizeOfHeapReserve', type: 'uint32', description: 'Heap reserve size' },
			{ name: 'SizeOfHeapCommit', type: 'uint32', description: 'Heap commit size' },
			{ name: 'LoaderFlags', type: 'uint32', description: 'Loader flags' },
			{ name: 'NumberOfRvaAndSizes', type: 'uint32', description: 'Data directory count' }
		]
	},
	{
		name: 'Optional_Header64',
		description: 'PE32+ Optional Header',
		size: 240,
		fields: [
			{ name: 'Magic', type: 'uint16', description: 'Magic number (0x20B)' },
			{ name: 'MajorLinkerVersion', type: 'uint8', description: 'Linker major' },
			{ name: 'MinorLinkerVersion', type: 'uint8', description: 'Linker minor' },
			{ name: 'SizeOfCode', type: 'uint32', description: 'Code section size' },
			{ name: 'SizeOfInitializedData', type: 'uint32', description: 'Initialized data size' },
			{ name: 'SizeOfUninitializedData', type: 'uint32', description: 'Uninitialized data size' },
			{ name: 'AddressOfEntryPoint', type: 'uint32', description: 'Entry point RVA' },
			{ name: 'BaseOfCode', type: 'uint32', description: 'Code base RVA' },
			{ name: 'ImageBase', type: 'uint64', description: 'Image base address' },
			{ name: 'SectionAlignment', type: 'uint32', description: 'Section alignment' },
			{ name: 'FileAlignment', type: 'uint32', description: 'File alignment' },
			{ name: 'MajorOperatingSystemVersion', type: 'uint16', description: 'OS major version' },
			{ name: 'MinorOperatingSystemVersion', type: 'uint16', description: 'OS minor version' },
			{ name: 'MajorImageVersion', type: 'uint16', description: 'Image major version' },
			{ name: 'MinorImageVersion', type: 'uint16', description: 'Image minor version' },
			{ name: 'MajorSubsystemVersion', type: 'uint16', description: 'Subsystem major' },
			{ name: 'MinorSubsystemVersion', type: 'uint16', description: 'Subsystem minor' },
			{ name: 'Win32VersionValue', type: 'uint32', description: 'Reserved' },
			{ name: 'SizeOfImage', type: 'uint32', description: 'Image size' },
			{ name: 'SizeOfHeaders', type: 'uint32', description: 'Headers size' },
			{ name: 'CheckSum', type: 'uint32', description: 'Checksum' },
			{ name: 'Subsystem', type: 'uint16', description: 'Subsystem' },
			{ name: 'DllCharacteristics', type: 'uint16', description: 'DLL characteristics' },
			{ name: 'SizeOfStackReserve', type: 'uint64', description: 'Stack reserve size' },
			{ name: 'SizeOfStackCommit', type: 'uint64', description: 'Stack commit size' },
			{ name: 'SizeOfHeapReserve', type: 'uint64', description: 'Heap reserve size' },
			{ name: 'SizeOfHeapCommit', type: 'uint64', description: 'Heap commit size' },
			{ name: 'LoaderFlags', type: 'uint32', description: 'Loader flags' },
			{ name: 'NumberOfRvaAndSizes', type: 'uint32', description: 'Data directory count' }
		]
	},
	{
		name: 'Section_Header',
		description: 'PE Section Header',
		size: 40,
		fields: [
			{ name: 'Name', type: 'ascii', length: 8, description: 'Section name' },
			{ name: 'VirtualSize', type: 'uint32', description: 'Virtual size' },
			{ name: 'VirtualAddress', type: 'uint32', description: 'Virtual address' },
			{ name: 'SizeOfRawData', type: 'uint32', description: 'Raw data size' },
			{ name: 'PointerToRawData', type: 'uint32', description: 'Raw data offset' },
			{ name: 'PointerToRelocations', type: 'uint32', description: 'Relocations offset' },
			{ name: 'PointerToLinenumbers', type: 'uint32', description: 'Line numbers offset' },
			{ name: 'NumberOfRelocations', type: 'uint16', description: 'Relocation count' },
			{ name: 'NumberOfLinenumbers', type: 'uint16', description: 'Line number count' },
			{ name: 'Characteristics', type: 'uint32', description: 'Section characteristics' }
		]
	},
	{
		name: 'Data_Directory',
		description: 'PE Data Directory Entry',
		size: 8,
		fields: [
			{ name: 'VirtualAddress', type: 'uint32', description: 'Virtual address' },
			{ name: 'Size', type: 'uint32', description: 'Size' }
		]
	},
	{
		name: 'ELF_Header',
		description: 'ELF Executable Header',
		size: 64,
		fields: [
			{ name: 'e_ident_mag0', type: 'uint8', description: 'Magic 0x7F' },
			{ name: 'e_ident_mag1', type: 'uint8', description: 'Magic E' },
			{ name: 'e_ident_mag2', type: 'uint8', description: 'Magic L' },
			{ name: 'e_ident_mag3', type: 'uint8', description: 'Magic F' },
			{ name: 'e_ident_class', type: 'uint8', description: '32/64-bit' },
			{ name: 'e_ident_data', type: 'uint8', description: 'Endianness' },
			{ name: 'e_ident_version', type: 'uint8', description: 'ELF version' },
			{ name: 'e_ident_osabi', type: 'uint8', description: 'OS/ABI' },
			{ name: 'e_ident_abiversion', type: 'uint8', description: 'ABI version' },
			{ name: 'e_ident_pad', type: 'bytes', length: 7, description: 'Padding' },
			{ name: 'e_type', type: 'uint16', description: 'File type' },
			{ name: 'e_machine', type: 'uint16', description: 'Target machine' },
			{ name: 'e_version', type: 'uint32', description: 'Version' },
			{ name: 'e_entry', type: 'uint64', description: 'Entry point' },
			{ name: 'e_phoff', type: 'uint64', description: 'Program header offset' },
			{ name: 'e_shoff', type: 'uint64', description: 'Section header offset' },
			{ name: 'e_flags', type: 'uint32', description: 'Flags' },
			{ name: 'e_ehsize', type: 'uint16', description: 'Header size' },
			{ name: 'e_phentsize', type: 'uint16', description: 'Program header entry size' },
			{ name: 'e_phnum', type: 'uint16', description: 'Program header count' },
			{ name: 'e_shentsize', type: 'uint16', description: 'Section header entry size' },
			{ name: 'e_shnum', type: 'uint16', description: 'Section header count' },
			{ name: 'e_shstrndx', type: 'uint16', description: 'Section name string table index' }
		]
	},
	{
		name: 'MachO_Header',
		description: 'Mach-O Header (64-bit)',
		size: 32,
		fields: [
			{ name: 'magic', type: 'uint32', description: 'Magic (0xFEEDFACF)' },
			{ name: 'cputype', type: 'uint32', description: 'CPU type' },
			{ name: 'cpusubtype', type: 'uint32', description: 'CPU subtype' },
			{ name: 'filetype', type: 'uint32', description: 'File type' },
			{ name: 'ncmds', type: 'uint32', description: 'Number of load commands' },
			{ name: 'sizeofcmds', type: 'uint32', description: 'Size of load commands' },
			{ name: 'flags', type: 'uint32', description: 'Flags' },
			{ name: 'reserved', type: 'uint32', description: 'Reserved' }
		]
	},
	{
		name: 'IPv4_Header',
		description: 'IPv4 Packet Header',
		size: 20,
		fields: [
			{ name: 'Version_IHL', type: 'uint8', description: 'Version and IHL' },
			{ name: 'TOS', type: 'uint8', description: 'Type of service' },
			{ name: 'TotalLength', type: 'uint16', description: 'Total length' },
			{ name: 'Identification', type: 'uint16', description: 'Identification' },
			{ name: 'Flags_FragmentOffset', type: 'uint16', description: 'Flags and fragment offset' },
			{ name: 'TTL', type: 'uint8', description: 'Time to live' },
			{ name: 'Protocol', type: 'uint8', description: 'Protocol' },
			{ name: 'HeaderChecksum', type: 'uint16', description: 'Header checksum' },
			{ name: 'SourceIP', type: 'uint32', description: 'Source IP address' },
			{ name: 'DestIP', type: 'uint32', description: 'Destination IP address' }
		]
	},
	{
		name: 'TCP_Header',
		description: 'TCP Packet Header',
		size: 20,
		fields: [
			{ name: 'SrcPort', type: 'uint16', description: 'Source port' },
			{ name: 'DstPort', type: 'uint16', description: 'Destination port' },
			{ name: 'SeqNumber', type: 'uint32', description: 'Sequence number' },
			{ name: 'AckNumber', type: 'uint32', description: 'Acknowledgment number' },
			{ name: 'DataOffset_Reserved_Flags', type: 'uint16', description: 'Data offset and flags' },
			{ name: 'Window', type: 'uint16', description: 'Window size' },
			{ name: 'Checksum', type: 'uint16', description: 'Checksum' },
			{ name: 'UrgentPointer', type: 'uint16', description: 'Urgent pointer' }
		]
	},
	{
		name: 'UUID',
		description: 'UUID/GUID Structure',
		size: 16,
		fields: [
			{ name: 'Data1', type: 'uint32', description: 'Data 1' },
			{ name: 'Data2', type: 'uint16', description: 'Data 2' },
			{ name: 'Data3', type: 'uint16', description: 'Data 3' },
			{ name: 'Data4', type: 'bytes', length: 8, description: 'Data 4' }
		]
	},
	{
		name: 'FILETIME',
		description: 'Windows FILETIME',
		size: 8,
		fields: [
			{ name: 'dwLowDateTime', type: 'uint32', description: 'Low date time' },
			{ name: 'dwHighDateTime', type: 'uint32', description: 'High date time' }
		]
	},
	{
		name: 'Unix_Time32',
		description: 'Unix Timestamp (32-bit)',
		size: 4,
		fields: [
			{ name: 'timestamp', type: 'uint32', description: 'Seconds since epoch' }
		]
	},
	{
		name: 'Unix_Time64',
		description: 'Unix Timestamp (64-bit)',
		size: 8,
		fields: [
			{ name: 'timestamp', type: 'uint64', description: 'Seconds since epoch' }
		]
	}
];
