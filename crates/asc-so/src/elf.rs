use std::collections::BTreeSet;

use crate::{Error, Result};

/// ELF class from `e_ident`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Elf32,
    Elf64,
}

/// ELF endianness from `e_ident`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

/// `e_type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    None,
    Relocatable,
    Executable,
    Shared,
    Core,
    Other(u16),
}

impl ObjectKind {
    fn from_u16(value: u16) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Relocatable,
            2 => Self::Executable,
            3 => Self::Shared,
            4 => Self::Core,
            other => Self::Other(other),
        }
    }

    fn label(self) -> String {
        match self {
            Self::None => "NONE".to_string(),
            Self::Relocatable => "REL".to_string(),
            Self::Executable => "EXEC".to_string(),
            Self::Shared => "DYN".to_string(),
            Self::Core => "CORE".to_string(),
            Self::Other(value) => format!("0x{value:x}"),
        }
    }
}

/// File range of an executable section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodeSpan {
    pub offset: u64,
    pub address: u64,
    pub size: u64,
}

/// Address and size of one exported symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SymbolLoc {
    pub address: u64,
    pub size: u64,
}

/// One dynamic symbol. The name is the comparison key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
}

/// Header and dynamic linking facts for one shared object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElfInfo {
    pub class: Class,
    pub endian: Endian,
    pub kind: ObjectKind,
    pub machine: String,
    pub machine_id: u16,
    pub entry: u64,
    pub code: Vec<CodeSpan>,
    pub export_at: std::collections::BTreeMap<String, SymbolLoc>,
    pub soname: Option<String>,
    pub needed: BTreeSet<String>,
    pub imports: BTreeSet<String>,
    pub exports: BTreeSet<String>,
    /// Section headers and program headers disagreed, so the program headers were kept.
    pub program_headers_preferred: bool,
}

/// Fields and symbols that differ between two shared objects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElfDiff {
    pub header: Vec<(&'static str, String, String)>,
    pub needed_removed: Vec<String>,
    pub needed_added: Vec<String>,
    pub imports_removed: Vec<String>,
    pub imports_added: Vec<String>,
    pub exports_removed: Vec<String>,
    pub exports_added: Vec<String>,
}

impl ElfDiff {
    pub fn is_empty(&self) -> bool {
        self.header.is_empty()
            && self.needed_removed.is_empty()
            && self.needed_added.is_empty()
            && self.imports_removed.is_empty()
            && self.imports_added.is_empty()
            && self.exports_removed.is_empty()
            && self.exports_added.is_empty()
    }
}

impl ElfInfo {
    /// Parses an ELF object from both the section table and the program headers.
    ///
    /// Dynamic symbols and executable bytes are taken from the section table when
    /// the two views agree, or when the program headers cannot be read. When both
    /// views exist and disagree, the program headers win.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 16 || &data[0..4] != b"\x7fELF" {
            bail!("not an ELF file");
        }
        let class = match data[4] {
            1 => Class::Elf32,
            2 => Class::Elf64,
            other => bail!("unknown ELF class {other}"),
        };
        let endian = match data[5] {
            1 => Endian::Little,
            2 => Endian::Big,
            other => bail!("unknown ELF endian {other}"),
        };
        let reader = Reader {
            data,
            class,
            endian,
        };
        let header_size = if class == Class::Elf64 { 64 } else { 52 };
        if data.len() < header_size {
            bail!("truncated ELF header");
        }
        let kind = ObjectKind::from_u16(reader.u16(16)?);
        let machine_id = reader.u16(18)?;
        let machine = machine_name(machine_id);
        let entry = reader.addr(24)?;
        let shoff = reader.addr(if class == Class::Elf64 { 40 } else { 32 })?;
        let shentsize = reader.u16(if class == Class::Elf64 { 58 } else { 46 })? as usize;
        let shnum = usize::from(reader.u16(if class == Class::Elf64 { 60 } else { 48 })?);
        let phoff = reader.addr(if class == Class::Elf64 { 32 } else { 28 })?;
        let phentsize = usize::from(reader.u16(if class == Class::Elf64 { 54 } else { 42 })?);
        let phnum = usize::from(reader.u16(if class == Class::Elf64 { 56 } else { 44 })?);

        let info = Self {
            class,
            endian,
            kind,
            machine,
            machine_id,
            entry,
            code: Vec::new(),
            export_at: std::collections::BTreeMap::new(),
            soname: None,
            needed: BTreeSet::new(),
            imports: BTreeSet::new(),
            exports: BTreeSet::new(),
            program_headers_preferred: false,
        };

        let sections = match section_count(&reader, shoff, shentsize, shnum) {
            Ok(0) => Ok(None),
            Ok(count) => {
                let mut view = info.clone();
                view.load_sections(&reader, shoff, shentsize, count)
                    .map(|()| view)
                    .map(Some)
            }
            Err(err) => Err(err),
        };
        let program_headers = if phnum == 0 {
            Ok(None)
        } else {
            let mut view = info.clone();
            view.load_program_headers(&reader, phoff, phentsize, phnum)
                .map(|()| view)
                .map(Some)
        };
        choose_link(data, info, sections, program_headers)
    }

    pub fn diff(&self, other: &Self) -> ElfDiff {
        let mut header = Vec::new();
        push_field(
            &mut header,
            "class",
            class_label(self.class),
            class_label(other.class),
        );
        push_field(
            &mut header,
            "endian",
            endian_label(self.endian),
            endian_label(other.endian),
        );
        push_field(&mut header, "type", self.kind.label(), other.kind.label());
        push_field(
            &mut header,
            "machine",
            self.machine.clone(),
            other.machine.clone(),
        );
        push_field(
            &mut header,
            "entry",
            format!("{:#x}", self.entry),
            format!("{:#x}", other.entry),
        );
        match (&self.soname, &other.soname) {
            (left, right) if left != right => header.push((
                "soname",
                left.clone().unwrap_or_else(|| "-".to_string()),
                right.clone().unwrap_or_else(|| "-".to_string()),
            )),
            _ => {}
        }
        ElfDiff {
            header,
            needed_removed: removed(&self.needed, &other.needed),
            needed_added: removed(&other.needed, &self.needed),
            imports_removed: removed(&self.imports, &other.imports),
            imports_added: removed(&other.imports, &self.imports),
            exports_removed: removed(&self.exports, &other.exports),
            exports_added: removed(&other.exports, &self.exports),
        }
    }

    fn load_sections(
        &mut self,
        reader: &Reader<'_>,
        shoff: u64,
        entsize: usize,
        count: usize,
    ) -> Result<()> {
        let mut dynsym = None;
        let mut dynamic = None;
        for index in 0..count {
            let off = shoff + (index * entsize) as u64;
            let kind = reader.section_field(shoff, index, entsize, SectionField::Type)? as u32;
            let flags = reader.section_field(shoff, index, entsize, SectionField::Flags)?;
            if kind == 11 {
                dynsym = Some(off);
            } else if kind == 6 {
                dynamic = Some(off);
            }
            // SHF_EXECINSTR, and not SHT_NOBITS. These are the bytes worth disassembling.
            if flags & 4 != 0 && kind != 8 {
                let offset = reader.section_field(shoff, index, entsize, SectionField::Offset)?;
                let size = reader.section_field(shoff, index, entsize, SectionField::Size)?;
                let address = reader.section_field(shoff, index, entsize, SectionField::Addr)?;
                if size > 0 {
                    self.code.push(CodeSpan {
                        offset,
                        address,
                        size,
                    });
                }
            }
        }
        if let Some(off) = dynsym {
            let link = reader.section_field(
                shoff,
                section_index(shoff, off, entsize),
                entsize,
                SectionField::Link,
            )? as usize;
            let sym_off = reader.section_field(
                shoff,
                section_index(shoff, off, entsize),
                entsize,
                SectionField::Offset,
            )?;
            let sym_size = reader.section_field(
                shoff,
                section_index(shoff, off, entsize),
                entsize,
                SectionField::Size,
            )?;
            let str_off = reader.section_field(shoff, link, entsize, SectionField::Offset)?;
            let str_size = reader.section_field(shoff, link, entsize, SectionField::Size)?;
            self.read_symbols(reader, sym_off, sym_size, str_off, str_size)?;
        }
        if let Some(off) = dynamic {
            let index = section_index(shoff, off, entsize);
            let dyn_off = reader.section_field(shoff, index, entsize, SectionField::Offset)?;
            let dyn_size = reader.section_field(shoff, index, entsize, SectionField::Size)?;
            let link = reader.section_field(shoff, index, entsize, SectionField::Link)? as usize;
            let str_off = reader.section_field(shoff, link, entsize, SectionField::Offset)?;
            let str_size = reader.section_field(shoff, link, entsize, SectionField::Size)?;
            self.read_dynamic_tags(reader, dyn_off, dyn_size, str_off, str_size)?;
        }
        Ok(())
    }

    fn load_program_headers(
        &mut self,
        reader: &Reader<'_>,
        phoff: u64,
        entsize: usize,
        count: usize,
    ) -> Result<()> {
        let minimum = if reader.class == Class::Elf64 { 56 } else { 32 };
        if entsize < minimum {
            bail!("program header entry size is too small");
        }
        let mut dynamic = None;
        for index in 0..count {
            let off = phoff + u64::try_from(index * entsize).unwrap_or(u64::MAX);
            let kind = reader.u32_at(off)?;
            // PT_LOAD with PF_X, or PT_DYNAMIC.
            if kind == 1 {
                let flags = reader.phdr_flags(off)?;
                if flags & 1 != 0 {
                    let (offset, filesz, virt) = reader.phdr_load(off)?;
                    if filesz > 0 {
                        self.code.push(CodeSpan {
                            offset,
                            address: virt,
                            size: filesz,
                        });
                    }
                }
            } else if kind == 2 {
                let (offset, filesz) = reader.phdr_file(off)?;
                dynamic = Some((offset, filesz));
            }
        }
        let Some((dyn_off, dyn_size)) = dynamic else {
            return Ok(());
        };
        let tags = self.dynamic_entries(reader, dyn_off, dyn_size)?;
        let file_addr = |vaddr: u64| vaddr_to_offset(reader, phoff, entsize, count, vaddr);
        let str_off = tags
            .iter()
            .find(|(tag, _)| *tag == 5)
            .and_then(|(_, val)| file_addr(*val))
            .unwrap_or(0);
        let str_size = u64::try_from(reader.data.len())
            .unwrap_or(0)
            .saturating_sub(str_off);
        if let Some(sym_addr) = tags.iter().find(|(tag, _)| *tag == 6).map(|(_, val)| *val) {
            if let Some(sym_off) = file_addr(sym_addr) {
                let count = symbol_count(reader, &tags, phoff, entsize, count)?;
                let sym_entsize = if reader.class == Class::Elf64 { 24 } else { 16 };
                self.read_symbols(reader, sym_off, count * sym_entsize, str_off, str_size)?;
            }
        }
        self.read_dynamic_tags(reader, dyn_off, dyn_size, str_off, str_size)?;
        Ok(())
    }

    fn dynamic_entries(
        &self,
        reader: &Reader<'_>,
        offset: u64,
        size: u64,
    ) -> Result<Vec<(i64, u64)>> {
        let step = if reader.class == Class::Elf64 { 16 } else { 8 };
        let Some(end) = offset.checked_add(size) else {
            bail!("dynamic segment size overflows");
        };
        let cap = reader.data.len() / step + 1;
        let mut out = Vec::new();
        let mut at = offset;
        while at.saturating_add(u64::try_from(step).unwrap_or(u64::MAX)) <= end {
            if out.len() >= cap {
                bail!("dynamic segment is too large");
            }
            let (tag, val) = reader.dyn_entry(at)?;
            if tag == 0 {
                break;
            }
            out.push((tag, val));
            at += u64::try_from(step).unwrap_or(u64::MAX);
        }
        Ok(out)
    }

    fn read_dynamic_tags(
        &mut self,
        reader: &Reader<'_>,
        offset: u64,
        size: u64,
        str_off: u64,
        str_size: u64,
    ) -> Result<()> {
        for (tag, val) in self.dynamic_entries(reader, offset, size)? {
            if tag == 1 {
                if let Some(name) = reader.string_at(str_off, str_size, val) {
                    self.needed.insert(name);
                }
            } else if tag == 14 {
                self.soname = reader.string_at(str_off, str_size, val);
            }
        }
        Ok(())
    }

    fn read_symbols(
        &mut self,
        reader: &Reader<'_>,
        sym_off: u64,
        sym_size: u64,
        str_off: u64,
        str_size: u64,
    ) -> Result<()> {
        let step = if reader.class == Class::Elf64 { 24 } else { 16 };
        if step == 0 {
            return Ok(());
        }
        let count = sym_size / step;
        for index in 1..count {
            let at = sym_off + index * step;
            let raw = reader.symbol(at)?;
            let (name_off, info, shndx) = (raw.name, raw.info, raw.shndx);
            let Some(name) = reader.string_at(str_off, str_size, u64::from(name_off)) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let bind = info >> 4;
            if shndx == 0 {
                self.imports.insert(name);
            } else if bind == 1 || bind == 2 {
                self.export_at.insert(
                    name.clone(),
                    SymbolLoc {
                        address: raw.value,
                        size: raw.size,
                    },
                );
                self.exports.insert(name);
            }
        }
        Ok(())
    }
}

fn vaddr_to_offset(
    reader: &Reader<'_>,
    phoff: u64,
    entsize: usize,
    count: usize,
    vaddr: u64,
) -> Option<u64> {
    for index in 0..count {
        let off = phoff + (index * entsize) as u64;
        let kind = reader.u32_at(off).ok()?;
        if kind != 1 {
            continue;
        }
        let (offset, filesz, virt) = reader.phdr_load(off).ok()?;
        if vaddr >= virt && vaddr - virt < filesz {
            return Some(offset + (vaddr - virt));
        }
    }
    None
}

fn symbol_count(
    reader: &Reader<'_>,
    tags: &[(i64, u64)],
    phoff: u64,
    phentsize: usize,
    phnum: usize,
) -> Result<u64> {
    let file_addr = |vaddr: u64| {
        vaddr_to_offset(reader, phoff, phentsize, phnum, vaddr)
            .ok_or_else(|| Error::new("dynamic address is not in a load segment"))
    };
    if let Some((_, addr)) = tags.iter().find(|(tag, _)| *tag == 4) {
        // DT_HASH: nbucket, nchain, then nchain is the symbol count.
        let addr = file_addr(*addr)?;
        let nchain = reader.u32_at(addr + 4)?;
        return capped_symbols(u64::from(nchain));
    }
    if let Some((_, addr)) = tags.iter().find(|(tag, _)| *tag == 0x6fff_fef5) {
        // DT_GNU_HASH. The last bucket's chain ends at a symbol whose low bit is 1.
        let addr = file_addr(*addr)?;
        let nbuckets = u64::from(reader.u32_at(addr)?);
        if nbuckets > MAX_SYMBOLS {
            bail!("dynamic symbol hash is too large");
        }
        let symoffset = u64::from(reader.u32_at(addr + 4)?);
        let bloom_size = u64::from(reader.u32_at(addr + 8)?);
        let bloom_bytes = bloom_size * if reader.class == Class::Elf64 { 8 } else { 4 };
        let buckets = addr + 16 + bloom_bytes;
        let chains = buckets + nbuckets * 4;
        let mut max_sym = symoffset;
        for index in 0..nbuckets {
            let bucket = reader.u32_at(buckets + index * 4)? as u64;
            if bucket < symoffset {
                continue;
            }
            let mut symbol = bucket;
            let mut walked = 0u64;
            loop {
                if walked >= MAX_SYMBOLS {
                    bail!("dynamic symbol hash does not terminate");
                }
                walked += 1;
                max_sym = max_sym.max(symbol.saturating_add(1));
                let chain = reader.u32_at(chains + (symbol - symoffset) * 4)?;
                if chain & 1 == 1 {
                    break;
                }
                symbol = symbol.saturating_add(1);
            }
        }
        return capped_symbols(max_sym);
    }
    bail!("dynamic symbol count is missing");
}

const MAX_SYMBOLS: u64 = 1_000_000;

fn capped_symbols(count: u64) -> Result<u64> {
    if count > MAX_SYMBOLS {
        bail!("dynamic symbol count is too large");
    }
    Ok(count)
}

fn section_count(reader: &Reader<'_>, shoff: u64, entsize: usize, shnum: usize) -> Result<usize> {
    if shnum == 0 && shoff == 0 {
        return Ok(0);
    }
    if entsize == 0 {
        bail!("section entry size is zero");
    }
    let count = if shnum == 0 {
        let size = reader.section_field(shoff, 0, entsize, SectionField::Size)?;
        usize::try_from(size).map_err(|_| Error::new("section count is too large"))?
    } else {
        shnum
    };
    if count > 1_000_000 {
        bail!("section count is too large");
    }
    Ok(count)
}

fn choose_link(
    bytes: &[u8],
    base: ElfInfo,
    sections: Result<Option<ElfInfo>>,
    program_headers: Result<Option<ElfInfo>>,
) -> Result<ElfInfo> {
    match (sections, program_headers) {
        (Ok(None), Ok(None)) => Ok(base),
        (Ok(Some(section)), Ok(None) | Err(_)) => Ok(section),
        (Ok(None) | Err(_), Ok(Some(program_headers))) => Ok(program_headers),
        (Ok(Some(section)), Ok(Some(program_headers))) => {
            if link_agrees(bytes, &section, &program_headers) {
                Ok(section)
            } else {
                let mut program_headers = program_headers;
                program_headers.program_headers_preferred = true;
                Ok(program_headers)
            }
        }
        (Ok(None), Err(err)) | (Err(err), Ok(None) | Err(_)) => Err(err),
    }
}

fn link_agrees(bytes: &[u8], section: &ElfInfo, program_headers: &ElfInfo) -> bool {
    section.soname == program_headers.soname
        && section.needed == program_headers.needed
        && section.imports == program_headers.imports
        && section.exports == program_headers.exports
        && section.export_at == program_headers.export_at
        && code_agrees(bytes, &section.code, &program_headers.code)
}

fn code_agrees(bytes: &[u8], sections: &[CodeSpan], program_headers: &[CodeSpan]) -> bool {
    if sections.is_empty() && program_headers.is_empty() {
        return true;
    }
    if sections.is_empty() || program_headers.is_empty() {
        return false;
    }
    sections.iter().all(|span| {
        let Some(outer) = program_headers.iter().find(|item| covers(item, span)) else {
            return false;
        };
        let Some(delta) = span.address.checked_sub(outer.address) else {
            return false;
        };
        let Some(offset) = outer.offset.checked_add(delta) else {
            return false;
        };
        file_bytes(bytes, span.offset, span.size) == file_bytes(bytes, offset, span.size)
    })
}

fn covers(outer: &CodeSpan, inner: &CodeSpan) -> bool {
    let Some(inner_end) = inner.address.checked_add(inner.size) else {
        return false;
    };
    let Some(outer_end) = outer.address.checked_add(outer.size) else {
        return false;
    };
    inner.address >= outer.address && inner_end <= outer_end
}

fn file_bytes(bytes: &[u8], offset: u64, size: u64) -> &[u8] {
    let Ok(start) = usize::try_from(offset) else {
        return &[];
    };
    let Ok(len) = usize::try_from(size) else {
        return bytes.get(start..).unwrap_or(&[]);
    };
    bytes
        .get(start..start.saturating_add(len).min(bytes.len()))
        .unwrap_or(&[])
}

fn section_index(shoff: u64, offset: u64, entsize: usize) -> usize {
    ((offset - shoff) / entsize as u64) as usize
}

enum SectionField {
    Type,
    Flags,
    Addr,
    Offset,
    Size,
    Link,
}

struct RawSym {
    name: u32,
    info: u8,
    shndx: u16,
    value: u64,
    size: u64,
}

struct Reader<'a> {
    data: &'a [u8],
    class: Class,
    endian: Endian,
}

impl Reader<'_> {
    fn u16(&self, offset: usize) -> Result<u16> {
        let bytes = self.take(offset, 2)?;
        Ok(match self.endian {
            Endian::Little => u16::from_le_bytes([bytes[0], bytes[1]]),
            Endian::Big => u16::from_be_bytes([bytes[0], bytes[1]]),
        })
    }

    fn u32_at(&self, offset: u64) -> Result<u32> {
        let offset = usize::try_from(offset).map_err(|_| Error::new("ELF offset is too large"))?;
        let bytes = self.take(offset, 4)?;
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            Endian::Big => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        })
    }

    fn u64_at(&self, offset: u64) -> Result<u64> {
        let offset = usize::try_from(offset).map_err(|_| Error::new("ELF offset is too large"))?;
        let bytes = self.take(offset, 8)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(bytes);
        Ok(match self.endian {
            Endian::Little => u64::from_le_bytes(buf),
            Endian::Big => u64::from_be_bytes(buf),
        })
    }

    fn addr(&self, offset: usize) -> Result<u64> {
        if self.class == Class::Elf64 {
            self.u64_at(offset as u64)
        } else {
            Ok(u64::from(self.u32_at(offset as u64)?))
        }
    }

    fn section_field(
        &self,
        shoff: u64,
        index: usize,
        entsize: usize,
        field: SectionField,
    ) -> Result<u64> {
        let base = shoff + (index * entsize) as u64;
        let is_64 = self.class == Class::Elf64;
        let at = match field {
            SectionField::Type => base + 4,
            SectionField::Flags => base + 8,
            SectionField::Addr => base + if is_64 { 16 } else { 12 },
            SectionField::Link => base + if is_64 { 40 } else { 24 },
            SectionField::Offset => base + if is_64 { 24 } else { 16 },
            SectionField::Size => base + if is_64 { 32 } else { 20 },
        };
        if matches!(field, SectionField::Type | SectionField::Link) || !is_64 {
            Ok(u64::from(self.u32_at(at)?))
        } else {
            self.u64_at(at)
        }
    }

    fn phdr_file(&self, offset: u64) -> Result<(u64, u64)> {
        let (offset, filesz, _) = self.phdr_load(offset)?;
        Ok((offset, filesz))
    }

    fn phdr_flags(&self, offset: u64) -> Result<u32> {
        let at = if self.class == Class::Elf64 {
            offset + 4
        } else {
            offset + 24
        };
        self.u32_at(at)
    }

    fn phdr_load(&self, offset: u64) -> Result<(u64, u64, u64)> {
        if self.class == Class::Elf64 {
            Ok((
                self.u64_at(offset + 8)?,
                self.u64_at(offset + 32)?,
                self.u64_at(offset + 16)?,
            ))
        } else {
            Ok((
                u64::from(self.u32_at(offset + 4)?),
                u64::from(self.u32_at(offset + 16)?),
                u64::from(self.u32_at(offset + 8)?),
            ))
        }
    }

    fn dyn_entry(&self, offset: u64) -> Result<(i64, u64)> {
        if self.class == Class::Elf64 {
            let tag = self.u64_at(offset)? as i64;
            let val = self.u64_at(offset + 8)?;
            Ok((tag, val))
        } else {
            let tag = self.u32_at(offset)? as i32 as i64;
            let val = u64::from(self.u32_at(offset + 4)?);
            Ok((tag, val))
        }
    }

    fn symbol(&self, offset: u64) -> Result<RawSym> {
        let name = self.u32_at(offset)?;
        let at = |add: u64| {
            usize::try_from(offset + add).map_err(|_| Error::new("ELF offset is too large"))
        };
        if self.class == Class::Elf64 {
            Ok(RawSym {
                name,
                info: self.take(at(4)?, 1)?[0],
                shndx: self.u16(at(6)?)?,
                value: self.u64_at(offset + 8)?,
                size: self.u64_at(offset + 16)?,
            })
        } else {
            Ok(RawSym {
                name,
                info: self.take(at(12)?, 1)?[0],
                shndx: self.u16(at(14)?)?,
                value: u64::from(self.u32_at(offset + 4)?),
                size: u64::from(self.u32_at(offset + 8)?),
            })
        }
    }

    fn string_at(&self, str_off: u64, str_size: u64, name_off: u64) -> Option<String> {
        if name_off >= str_size {
            return None;
        }
        let start = usize::try_from(str_off + name_off).ok()?;
        let end_limit = usize::try_from(str_off + str_size).ok()?;
        let bytes = self.data.get(start..end_limit.min(self.data.len()))?;
        let end = bytes.iter().position(|byte| *byte == 0)?;
        Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }

    fn take(&self, offset: usize, len: usize) -> Result<&[u8]> {
        self.data
            .get(offset..offset + len)
            .ok_or_else(|| Error::new("truncated ELF"))
    }
}

pub(crate) const EM_386: u16 = 3;
pub(crate) const EM_ARM: u16 = 40;
pub(crate) const EM_X86_64: u16 = 62;
pub(crate) const EM_AARCH64: u16 = 183;
pub(crate) const EM_RISCV: u16 = 243;

pub(crate) fn machine_name(value: u16) -> String {
    match value {
        EM_386 => "X86".to_string(),
        EM_ARM => "ARM".to_string(),
        EM_X86_64 => "X86_64".to_string(),
        EM_AARCH64 => "AARCH64".to_string(),
        EM_RISCV => "RISCV".to_string(),
        other => format!("EM_{other}"),
    }
}

fn class_label(class: Class) -> String {
    match class {
        Class::Elf32 => "ELF32".to_string(),
        Class::Elf64 => "ELF64".to_string(),
    }
}

fn endian_label(endian: Endian) -> String {
    match endian {
        Endian::Little => "little".to_string(),
        Endian::Big => "big".to_string(),
    }
}

fn push_field(
    out: &mut Vec<(&'static str, String, String)>,
    name: &'static str,
    left: String,
    right: String,
) {
    if left != right {
        out.push((name, left, right));
    }
}

fn removed(left: &BTreeSet<String>, right: &BTreeSet<String>) -> Vec<String> {
    left.difference(right).cloned().collect()
}
