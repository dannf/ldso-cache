// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ldsocache

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unsafe"
)

const ldsoMagic = "glibc-ld.so.cache"
const ldsoVersion = "1.1"
const ldsoExtensionMagic = 0xEAA42174
const cacheExtensionTagGenerator = uint32(1)

const (
	FLAG_ANY                    uint32 = 0xffff
	FLAG_TYPE_MASK              uint32 = 0x00ff
	FLAG_LIBC4                  uint32 = 0x0000
	FLAG_ELF                    uint32 = 0x0001
	FLAG_ELF_LIBC5              uint32 = 0x0002
	FLAG_ELF_LIBC6              uint32 = 0x0003
	FLAG_REQUIRED_MASK          uint32 = 0xff00
	FLAG_SPARC_LIB64            uint32 = 0x0100
	FLAG_X8664_LIB64            uint32 = 0x0300
	FLAG_S390_LIB64             uint32 = 0x0400
	FLAG_POWERPC_LIB64          uint32 = 0x0500
	FLAG_MIPS64_LIBN32          uint32 = 0x0600
	FLAG_MIPS64_LIBN64          uint32 = 0x0700
	FLAG_X8664_LIBX32           uint32 = 0x0800
	FLAG_ARM_LIBHF              uint32 = 0x0900
	FLAG_AARCH64_LIB64          uint32 = 0x0a00
	FLAG_ARM_LIBSF              uint32 = 0x0b00
	FLAG_MIPS_LIB32_NAN2008     uint32 = 0x0c00
	FLAG_MIPS64_LIBN32_NAN2008  uint32 = 0x0d00
	FLAG_MIPS64_LIBN64_NAN2008  uint32 = 0x0e00
	FLAG_RISCV_FLOAT_ABI_SOFT   uint32 = 0x0f00
	FLAG_RISCV_FLOAT_ABI_DOUBLE uint32 = 0x1000
	FLAG_LARCH_FLOAT_ABI_SOFT   uint32 = 0x1100
	FLAG_LARCH_FLOAT_ABI_DOUBLE uint32 = 0x1200
)

type LDSORawCacheHeader struct {
	Magic   [17]byte
	Version [3]byte

	NumLibs      uint32
	StrTableSize uint32

	Flags   uint8
	Unused0 [3]byte

	ExtOffset uint32

	Unused1 [3]uint32
}

type LDSORawCacheEntry struct {
	Flags uint32

	// Offsets in string table.
	Key   uint32
	Value uint32

	OSVersion_Needed uint32
	HWCap_Needed     uint64
}

type LDSOCacheEntry struct {
	Flags uint32

	Name string

	OSVersion_Needed uint32
	HWCap_Needed     uint64
}

type LDSOCacheExtensionHeader struct {
	Magic uint32
	Count uint32
}

type LDSOCacheExtensionSectionHeader struct {
	Tag    uint32
	Flags  uint32
	Offset uint32
	Size   uint32
}

type LDSOCacheExtensionSection struct {
	Header LDSOCacheExtensionSectionHeader
	Data   []byte
}

type LDSOCacheFile struct {
	Header     LDSORawCacheHeader
	Entries    []LDSOCacheEntry
	Extensions []LDSOCacheExtensionSection
}

func (hdr *LDSORawCacheHeader) describe() {
	fmt.Printf("Header:\n")
	fmt.Printf("  Magic [%s]\n", hdr.Magic)
	fmt.Printf("  Version [%s]\n", hdr.Version)
	fmt.Printf("  %d library entries.\n", hdr.NumLibs)
	fmt.Printf("  String table is %d bytes long.\n", hdr.StrTableSize)
}

func (ehdr *LDSOCacheExtensionHeader) describe() {
	fmt.Printf("Extension header:\n")
	fmt.Printf("  %d entries.\n", ehdr.Count)
}

func (shdr *LDSOCacheExtensionSectionHeader) describe() {
	fmt.Printf("Extension section header:\n")
	fmt.Printf("  Tag [%d]\n", shdr.Tag)
	fmt.Printf("  Flags [%x]\n", shdr.Flags)
	fmt.Printf("  Offset [%d]\n", shdr.Offset)
	fmt.Printf("  Size [%d]\n", shdr.Size)
}

func ParseLDSOConf(fsys fs.FS, ldsoconf string) ([]string, error) {
	conf, err := fsys.Open(ldsoconf)
	if err != nil {
		fmt.Printf("Warning: Could not open config file %s\n", ldsoconf)
		return nil, err
	}
	defer conf.Close()
	contents, err := io.ReadAll(conf)
	if err != nil {
		fmt.Printf("Warning: Could not read config file %s\n", ldsoconf)
		return nil, err
	}
	var libpaths []string
	var seenpaths []string

	lines := strings.Split(string(contents), "\n")
	for _, line := range lines {
		idx := strings.Index(line, "#")
		if idx > -1 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		glob, is_include := strings.CutPrefix(line, "include ")
		if is_include {
			glob = strings.TrimSpace(glob)
			glob = strings.TrimLeft(glob, "/")
			matches, err := fs.Glob(fsys, glob)
			if err != nil {
				fmt.Printf("Warning: glob error in %s: %s", ldsoconf, glob)
				continue
			}
			if len(matches) == 0 {
				fmt.Printf("Warning: No matches for glob %s in %s\n", glob, ldsoconf)
			}

			for _, match := range matches {
				incpaths, err := ParseLDSOConf(fsys, match)
				if err != nil {
					fmt.Printf("Warning: Could not parse config file %s\n", match)
					continue
				}
				libpaths = append(libpaths, incpaths...)
			}
			return libpaths, nil
		}
		if _, err := fs.Stat(fsys, line); os.IsNotExist(err) {
			continue
		}
		// Avoid duplicates from e.g. /lib -> /usr/lib.
		//realpath, err := filepath.EvalSymlinks(line)
		realpath := line
		//fmt.Printf("DEBUG: Converting %s to realpath %s\n", line, realpath)

		if err != nil {
			return nil, err
		}
		if slices.Contains(seenpaths, realpath) {
			fmt.Printf("Warning: Skipping %s because we've already seen it\n", realpath)
			continue
		}
		libpaths = append(libpaths, line)
		seenpaths = append(seenpaths, realpath)
	}
	return libpaths, nil
}

type SoLib string
type SoVer string

type SoName struct {
	lib SoLib
	ver SoVer
}

type DynLib struct {
	soname *SoName
	entry *LDSOCacheEntry
	is_link bool
}

func parse_soname(soname string) (*SoName, error) {
	var so_lib SoLib
	var so_ver SoVer

	//fmt.Printf("DEBUG: Parsing soname %s\n", soname)
	if strings.HasSuffix(soname, ".so") {
		so_lib = SoLib(strings.TrimRight(soname, ".so"))
		so_ver = SoVer("")
	} else {
		pieces := strings.Split(soname, ".so.")
		if len(pieces) < 2 {
			return nil, fmt.Errorf("Invalid SONAME %s", soname)
		}
		so_lib = SoLib(strings.Join(pieces[:len(pieces)-2], ".so."))
		so_ver = SoVer(pieces[len(pieces)-1])
	}
	s := &SoName {
		lib: so_lib,
		ver: so_ver,
	}

	return s, nil
}

func soname_cmp(a SoVer, b SoVer) (int, error) {
	a_dots := strings.Split(string(a), ".")
	b_dots := strings.Split(string(b), ".")

	for i := 0; i < min(len(a_dots), len(b_dots)); i++ {
		if a_dots[i] == b_dots[i] {
			continue
		}
		do_string_compare := false
		a_int, err := strconv.Atoi(a_dots[i])
		if err != nil {
			do_string_compare = true
		}
		b_int, err := strconv.Atoi(b_dots[i])
		if err != nil {
			do_string_compare = true
		}
		if do_string_compare {
			if a_dots[i] < b_dots[i] {
				return -1, nil
			}
			return 1, nil
		}
		if a_int < b_int {
			return -1, nil
		}
		return 1, nil
	}
	if len(a) < len(b) {
		return -1, nil
	}
	if len(a) > len(b) {
		return 1, nil
	}
	return 0, nil
}

func BuildLDSOCacheEntries(fsys fs.FS, libdir string) ([]LDSOCacheEntry, error) {
	somap := make(map[string]DynLib)

	// fs.FS wants all file paths to be relative
	libdir = strings.TrimLeft(libdir, "/")
	dirents, err := fs.ReadDir(fsys, libdir)
	if err != nil {
		// It is OK for a directory to not exist
		return nil, nil
	}

	for _, dirent := range dirents {
		name := dirent.Name()
		// ldconfig(8) says it "will look only at files that are named lib*.so*
		// (for regular shared objects) or ld-*.so* (for the dynamic loader itself).
		// Other files will be ignored.
		if !strings.HasPrefix(name, "lib") && !strings.HasPrefix(name, "ld-") {
			continue
		}
		if !strings.Contains(name, "so") {
			continue
		}
		mode := dirent.Type()
		is_link := (mode & fs.ModeSymlink != 0)
		if !mode.IsRegular() && !is_link {
			continue
		}
		fullpath := filepath.Join(libdir, name)
		libf, err := fsys.Open(fullpath)
		if err != nil {
			continue
		}
		defer libf.Close()
		// Ugly hack.
		// We could call elf.NewFile(libf) here, but that only works
		// if libf implements ReadAt. apko's tarfs does not. Work
		// around that by reading the file into memory first.
		var buf []byte
		buf, err = fs.ReadFile(fsys, fullpath)
		libf.Close()
		r := bytes.NewReader(buf)
		if err != nil {
			fmt.Printf("DEBUG: Unable to read %s\n", fullpath)
			continue
		}
		elflibf, err := elf.NewFile(r)
		if err != nil {
			fmt.Printf("DEBUG: Unable to open %s as ELF\n", fullpath)
			continue
		}
		// FIXME: do we need to check for the ELF magic bytes?
		if elflibf.FileHeader.Type != elf.ET_DYN {
			continue
		}
		flags := uint32(0)
		flags |= FLAG_ELF
		// FIXME: Shouldn't just assert this
		flags |= FLAG_ELF_LIBC6
		sonames, err := elflibf.DynString(elf.DT_SONAME)
		if err != nil {
			continue
		}
		switch elflibf.FileHeader.Machine {
		case elf.EM_X86_64:
			flags |= FLAG_X8664_LIB64
		case elf.EM_AARCH64:
			flags |= FLAG_AARCH64_LIB64
		// FIXME: Add other architectures
		default:
			return nil, nil
		}
		libf.Close()
		for _, soname := range(sonames) {
			s, err := parse_soname(soname)
			if err != nil {
				return nil, err
			}
			if s == nil {
				continue
			}
			entry := LDSOCacheEntry{
				// fullpath is relative to "/"
				Name: filepath.Join("/", fullpath),
				Flags: flags,
				OSVersion_Needed: 0,
				HWCap_Needed: 0,
			}
			dynlib := DynLib{
				soname: s,
				is_link: is_link,
				entry: &entry,
			}
			current, exists := somap[soname]
			if !exists {
				somap[soname] = dynlib
				continue
			}
			cmp, err := soname_cmp(s.ver, current.soname.ver)
			if err != nil {
				return nil, err
			}
			if cmp < 1 {
				continue
			}
			if cmp < 0 || current.is_link && !dynlib.is_link {
				somap[soname] = dynlib
			}
		}
	}
	entries := make([]LDSOCacheEntry, len(somap))
	i := 0
	for _, value := range somap {
		entries[i] = *value.entry
		i++
	}
	return entries, nil
}

func BuildCacheFileForDirs(fsys fs.FS, libdirs []string) (*LDSOCacheFile, error) {
	all_entries := []LDSOCacheEntry{}

	for _, libdir := range libdirs {
		entries, err := BuildLDSOCacheEntries(fsys, libdir)
		if err != nil {
			return nil, err
		}
		all_entries = append(all_entries, entries...)
	}

	var magic [17]byte
	var version [3]byte
	copy(magic[:], ldsoMagic)
	copy(version[:], ldsoVersion)

	header := LDSORawCacheHeader{
		Magic: magic,
		Version: version,
		NumLibs: (uint32)(len(all_entries)),
	}

	cf := LDSOCacheFile{
		Header:  header,
		Entries: all_entries,
	}

	return &cf, nil
}

func BuildCacheFileForConfig(fsys fs.FS, cfgpath string) (*LDSOCacheFile, error) {
	libdirs, err := ParseLDSOConf(fsys, cfgpath)
	if err != nil {
		return nil, err
	}
	cf, err := BuildCacheFileForDirs(fsys, libdirs)
	if err != nil {
		return nil, err
	}
	return cf, nil
}

// LoadCacheFile attempts to load a cache file from disk.  When
// successful, it returns an LDSOCacheFile pointer which contains
// all relevant information from the cache file.
func LoadCacheFile(path string) (*LDSOCacheFile, error) {
	bindata, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(bindata)

	// TODO(kaniini): Use binary.BigEndian for BE targets.
	header := LDSORawCacheHeader{}
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	rawlibs := []LDSORawCacheEntry{}
	for i := uint32(0); i < header.NumLibs; i++ {
		rawlib := LDSORawCacheEntry{}
		if err := binary.Read(r, binary.LittleEndian, &rawlib); err != nil {
			return nil, err
		}

		rawlibs = append(rawlibs, rawlib)
	}

	pos, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}

	// The string table is a series of nul-terminated C strings.
	strtable := make([]byte, header.StrTableSize)
	if _, err := r.Read(strtable); err != nil {
		return nil, err
	}

	// Now build the cache index itself.
	entries := []LDSOCacheEntry{}
	for _, rawlib := range rawlibs {
		entry := LDSOCacheEntry{
			Flags:            rawlib.Flags,
			OSVersion_Needed: rawlib.OSVersion_Needed,
			HWCap_Needed:     rawlib.HWCap_Needed,
		}

		name, err := extractShlibName(strtable, rawlib.Value-uint32(pos))
		if err != nil {
			return nil, err
		}

		entry.Name = name

		entries = append(entries, entry)
	}

	// Extension data begins at the next 4-byte aligned position.
	pos, err = r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}

	// Align to nearest 4 byte boundary.
	//alignedPos := (pos & ^(0x1000 - 1)) + 0x1000
	alignedPos := ((pos & -16) + 8)
	pos, err = r.Seek(alignedPos, io.SeekStart)
	if err != nil {
		return nil, err
	}

	file := LDSOCacheFile{
		Header:  header,
		Entries: entries,
	}

	// Check for a cache extension section.
	extHeader := LDSOCacheExtensionHeader{}
	if err := binary.Read(r, binary.LittleEndian, &extHeader); err != nil {
		return &file, nil
	}
	if extHeader.Magic != ldsoExtensionMagic {
		return &file, nil
	}

	// Parse the extension chunks we understand.
	sections := []*LDSOCacheExtensionSection{}
	for i := uint32(0); i < extHeader.Count; i++ {
		sectionHeader := LDSOCacheExtensionSectionHeader{}
		if err := binary.Read(r, binary.LittleEndian, &sectionHeader); err != nil {
			return &file, nil
		}

		section := &LDSOCacheExtensionSection{Header: sectionHeader}
		sections = append(sections, section)
	}

	// Load extension data.
	for _, section := range sections {
		pos, err = r.Seek(int64(section.Header.Offset), io.SeekStart)
		if err != nil {
			return &file, nil
		}
		if pos != int64(section.Header.Offset) {
			return &file, nil
		}

		section.Data = make([]byte, section.Header.Size)
		if _, err := r.Read(section.Data); err != nil {
			return &file, nil
		}
	}

	for _, section := range sections {
		file.Extensions = append(file.Extensions, *section)
	}

	return &file, nil
}

// extractShlibName extracts a shared library from the string table.
func extractShlibName(strtable []byte, startIdx uint32) (string, error) {
	subset := strtable[startIdx:]
	terminatorPos := bytes.IndexByte(subset, 0x0)

	if terminatorPos == -1 {
		return string(subset), nil
	}

	return string(subset[:terminatorPos]), nil
}

func (cf *LDSOCacheFile) Write(w io.Writer) (error) {
	buf := &bytes.Buffer{}

	// Calculate the size of the file entry table for use
	// when calculating the file entry string table offsets.
	fileEntryTableSize := int(unsafe.Sizeof(LDSORawCacheHeader{}) + (uintptr(len(cf.Entries)) * unsafe.Sizeof(LDSORawCacheEntry{})))

	// Build the string table.
	lrcEntries := []LDSORawCacheEntry{}
	stringTable := []byte{}
	for _, lib := range cf.Entries {
		cursor := uint32(fileEntryTableSize) + uint32(len(stringTable))
		entry := []byte(lib.Name)
		entry = append(entry, byte(0x0))
		stringTable = append(stringTable, entry...)

		lrcEntry := LDSORawCacheEntry{
			Flags: lib.Flags,
			Key: cursor + uint32(len(filepath.Dir(lib.Name))+1),
			Value: cursor,
			OSVersion_Needed: lib.OSVersion_Needed,
			HWCap_Needed: lib.HWCap_Needed,
		}

		lrcEntries = append(lrcEntries, lrcEntry)
	}

	// Write the header section.
	cf.Header.NumLibs = uint32(len(lrcEntries))
	cf.Header.StrTableSize = uint32(len(stringTable))
	if err := cf.Header.Write(buf); err != nil {
		return err
	}

	// Write the file entry table.
	if err := binary.Write(buf, binary.LittleEndian, &lrcEntries); err != nil {
		return err
	}

	// Write the string table.
	if _, err := buf.Write(stringTable); err != nil {
		return err
	}

	pos := buf.Len()
	alignedPos := int(uint(pos) | (^uint(0) & 0x1000) + 0x1000)
	fmt.Printf("alignedPos: %d, pos: %d\n",alignedPos, pos)

	pad := make([]byte, alignedPos - pos)
	if _, err := buf.Write(pad); err != nil {
		return err
	}

	// Write the extension sections.
	if len(cf.Extensions) > 0 {
		ehdr := LDSOCacheExtensionHeader{
			Magic: ldsoExtensionMagic,
			Count: uint32(len(cf.Extensions)),
		}

		if err := binary.Write(buf, binary.LittleEndian, &ehdr); err != nil {
			return err
		}

		for _, ext := range cf.Extensions {
			if err := binary.Write(buf, binary.LittleEndian, ext.Header); err != nil {
				return err
			}
		}

		for _, ext := range cf.Extensions {
			if _, err := buf.Write(ext.Data); err != nil {
				return err
			}
		}
	}

	_, err := io.Copy(w, buf)
	return err
}

// Write writes a header for a cache file to disk.
func (hdr *LDSORawCacheHeader) Write(w io.Writer) error {
	if err := binary.Write(w, binary.LittleEndian, hdr); err != nil {
		return err
	}

	return nil
}
