use asc_so::ElfInfo;

/// ELF64 little-endian shared object with one import, one export, and DT_NEEDED.
fn shared_object(export: &str, import: &str, needed: &str) -> Vec<u8> {
    fn cstr(text: &str) -> Vec<u8> {
        let mut out = text.as_bytes().to_vec();
        out.push(0);
        out
    }
    let mut strings = vec![0u8];
    let export_off = strings.len() as u32;
    strings.extend(cstr(export));
    let import_off = strings.len() as u32;
    strings.extend(cstr(import));
    let needed_off = strings.len() as u32;
    strings.extend(cstr(needed));
    let soname_off = strings.len() as u32;
    strings.extend(cstr("libdemo.so"));

    let mut dynsym = vec![0u8; 24];
    dynsym.extend(symbol(import_off, 0, 0x12));
    dynsym.extend(symbol(export_off, 1, 0x12));

    let mut dynamic = Vec::new();
    dynamic.extend(dyn_tag(1, u64::from(needed_off)));
    dynamic.extend(dyn_tag(14, u64::from(soname_off)));
    dynamic.extend(dyn_tag(0, 0));

    let header = 64usize;
    let shentsize = 64usize;
    let shoff = header;
    let shnum = 4usize;
    let sections = shoff + shnum * shentsize;
    let dynsym_off = sections;
    let dynstr_off = dynsym_off + dynsym.len();
    let dynamic_off = dynstr_off + strings.len();

    let mut file = vec![0u8; dynamic_off + dynamic.len()];
    file[0..4].copy_from_slice(b"\x7fELF");
    file[4] = 2;
    file[5] = 1;
    file[6] = 1;
    file[16..18].copy_from_slice(&3u16.to_le_bytes());
    file[18..20].copy_from_slice(&183u16.to_le_bytes());
    file[20..24].copy_from_slice(&1u32.to_le_bytes());
    file[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    file[52..54].copy_from_slice(&64u16.to_le_bytes());
    file[58..60].copy_from_slice(&(shentsize as u16).to_le_bytes());
    file[60..62].copy_from_slice(&(shnum as u16).to_le_bytes());

    write_section(
        &mut file,
        shoff,
        shentsize,
        SectionSpec {
            index: 1,
            kind: 11,
            link: 2,
            offset: dynsym_off,
            size: dynsym.len(),
            entry: 24,
        },
    );
    write_section(
        &mut file,
        shoff,
        shentsize,
        SectionSpec {
            index: 2,
            kind: 3,
            link: 0,
            offset: dynstr_off,
            size: strings.len(),
            entry: 1,
        },
    );
    write_section(
        &mut file,
        shoff,
        shentsize,
        SectionSpec {
            index: 3,
            kind: 6,
            link: 2,
            offset: dynamic_off,
            size: dynamic.len(),
            entry: 16,
        },
    );
    file[dynsym_off..dynsym_off + dynsym.len()].copy_from_slice(&dynsym);
    file[dynstr_off..dynstr_off + strings.len()].copy_from_slice(&strings);
    file[dynamic_off..dynamic_off + dynamic.len()].copy_from_slice(&dynamic);
    file
}

fn symbol(name: u32, shndx: u16, info: u8) -> Vec<u8> {
    let mut out = vec![0u8; 24];
    out[0..4].copy_from_slice(&name.to_le_bytes());
    out[4] = info;
    out[6..8].copy_from_slice(&shndx.to_le_bytes());
    out
}

fn dyn_tag(tag: u64, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(&value.to_le_bytes());
    out
}

struct SectionSpec {
    index: usize,
    kind: u32,
    link: u32,
    offset: usize,
    size: usize,
    entry: u64,
}

fn write_section(file: &mut [u8], shoff: usize, entsize: usize, spec: SectionSpec) {
    let at = shoff + spec.index * entsize;
    file[at + 4..at + 8].copy_from_slice(&spec.kind.to_le_bytes());
    file[at + 24..at + 32].copy_from_slice(&(spec.offset as u64).to_le_bytes());
    file[at + 32..at + 40].copy_from_slice(&(spec.size as u64).to_le_bytes());
    file[at + 40..at + 44].copy_from_slice(&spec.link.to_le_bytes());
    file[at + 56..at + 64].copy_from_slice(&spec.entry.to_le_bytes());
}

#[test]
fn dynamic_symbols_and_needed_libraries_roundtrip() {
    let elf = ElfInfo::parse(&shared_object("bar", "foo", "libc.so")).unwrap();
    assert_eq!(elf.machine, "AARCH64");
    assert_eq!(elf.soname.as_deref(), Some("libdemo.so"));
    assert_eq!(
        elf.needed.iter().map(String::as_str).collect::<Vec<_>>(),
        vec!["libc.so"]
    );
    assert_eq!(
        elf.imports.iter().map(String::as_str).collect::<Vec<_>>(),
        vec!["foo"]
    );
    assert_eq!(
        elf.exports.iter().map(String::as_str).collect::<Vec<_>>(),
        vec!["bar"]
    );

    let other = ElfInfo::parse(&shared_object("baz", "foo", "libm.so")).unwrap();
    let diff = elf.diff(&other);
    assert_eq!(diff.exports_removed, vec!["bar".to_string()]);
    assert_eq!(diff.exports_added, vec!["baz".to_string()]);
    assert_eq!(diff.needed_removed, vec!["libc.so".to_string()]);
    assert_eq!(diff.needed_added, vec!["libm.so".to_string()]);
    assert!(diff.imports_added.is_empty());
}

#[test]
fn program_headers_win_when_symbols_contradict_sections() {
    let elf = ElfInfo::parse(&linked("bar", "real")).unwrap();
    assert!(elf.program_headers_preferred);
    assert_eq!(
        elf.exports.iter().map(String::as_str).collect::<Vec<_>>(),
        vec!["real"]
    );
    assert!(elf.imports.is_empty(), "{:?}", elf.imports);
}

#[test]
fn matching_program_headers_keep_the_section_view() {
    let elf = ElfInfo::parse(&linked("bar", "bar")).unwrap();
    assert!(!elf.program_headers_preferred);
    assert!(elf.exports.contains("bar"), "{:?}", elf.exports);
    assert!(elf.imports.contains("foo"), "{:?}", elf.imports);
    assert_eq!(elf.soname.as_deref(), Some("libdemo.so"));
}

#[test]
fn unreadable_program_headers_keep_sections() {
    let mut file = shared_object("bar", "foo", "libc.so");
    file[32..40].copy_from_slice(&0x00ff_ffffu64.to_le_bytes());
    file[54..56].copy_from_slice(&56u16.to_le_bytes());
    file[56..58].copy_from_slice(&1u16.to_le_bytes());
    let elf = ElfInfo::parse(&file).unwrap();
    assert!(!elf.program_headers_preferred);
    assert!(elf.exports.contains("bar"), "{:?}", elf.exports);
}

#[test]
fn executable_bytes_follow_program_headers_when_they_differ() {
    let (file, phdr_offset) = executable_conflict();
    let elf = ElfInfo::parse(&file).unwrap();
    assert!(elf.program_headers_preferred);
    assert_eq!(elf.code.len(), 1, "{:?}", elf.code);
    assert_eq!(elf.code[0].offset, phdr_offset);
    assert_eq!(elf.code[0].address, 0x1000);
}

fn linked(section_export: &str, phdr_export: &str) -> Vec<u8> {
    fn cstr(text: &str) -> Vec<u8> {
        let mut out = text.as_bytes().to_vec();
        out.push(0);
        out
    }
    let mut section_strings = vec![0u8];
    let section_export_off = u32::try_from(section_strings.len()).unwrap();
    section_strings.extend(cstr(section_export));
    let import_off = u32::try_from(section_strings.len()).unwrap();
    section_strings.extend(cstr("foo"));
    let section_needed_off = u32::try_from(section_strings.len()).unwrap();
    section_strings.extend(cstr("libc.so"));
    let section_soname_off = u32::try_from(section_strings.len()).unwrap();
    section_strings.extend(cstr("libdemo.so"));

    let mut section_dynsym = vec![0u8; 24];
    section_dynsym.extend(symbol(import_off, 0, 0x12));
    section_dynsym.extend(symbol(section_export_off, 1, 0x12));
    let mut section_dynamic = Vec::new();
    section_dynamic.extend(dyn_tag(1, u64::from(section_needed_off)));
    section_dynamic.extend(dyn_tag(14, u64::from(section_soname_off)));
    section_dynamic.extend(dyn_tag(0, 0));

    let mut phdr_strings = vec![0u8];
    let phdr_export_off = u32::try_from(phdr_strings.len()).unwrap();
    phdr_strings.extend(cstr(phdr_export));
    let phdr_import_off = (section_export == phdr_export).then(|| {
        let off = u32::try_from(phdr_strings.len()).unwrap();
        phdr_strings.extend(cstr("foo"));
        off
    });
    let phdr_needed_off = u32::try_from(phdr_strings.len()).unwrap();
    phdr_strings.extend(cstr("libc.so"));
    let phdr_soname_off = u32::try_from(phdr_strings.len()).unwrap();
    phdr_strings.extend(cstr("libdemo.so"));

    let mut phdr_dynsym = vec![0u8; 24];
    if let Some(off) = phdr_import_off {
        phdr_dynsym.extend(symbol(off, 0, 0x12));
    }
    phdr_dynsym.extend(symbol(phdr_export_off, 1, 0x12));
    let nchain = u32::try_from(phdr_dynsym.len() / 24).unwrap();
    let mut hash = Vec::new();
    hash.extend_from_slice(&1u32.to_le_bytes());
    hash.extend_from_slice(&nchain.to_le_bytes());
    hash.extend_from_slice(&0u32.to_le_bytes());
    for _ in 0..nchain {
        hash.extend_from_slice(&0u32.to_le_bytes());
    }

    let shoff = 64usize;
    let shentsize = 64usize;
    let mut cursor = shoff + 4 * shentsize;
    let sec_dynsym_off = cursor;
    cursor += section_dynsym.len();
    let sec_str_off = cursor;
    cursor += section_strings.len();
    let sec_dyn_off = cursor;
    cursor += section_dynamic.len();
    let ph_dynsym_off = cursor;
    cursor += phdr_dynsym.len();
    let ph_str_off = cursor;
    cursor += phdr_strings.len();
    let ph_hash_off = cursor;
    cursor += hash.len();
    let ph_dyn_off = cursor;

    let mut phdr_dynamic = Vec::new();
    phdr_dynamic.extend(dyn_tag(1, u64::from(phdr_needed_off)));
    phdr_dynamic.extend(dyn_tag(14, u64::from(phdr_soname_off)));
    phdr_dynamic.extend(dyn_tag(5, u64::try_from(ph_str_off).unwrap()));
    phdr_dynamic.extend(dyn_tag(6, u64::try_from(ph_dynsym_off).unwrap()));
    phdr_dynamic.extend(dyn_tag(4, u64::try_from(ph_hash_off).unwrap()));
    phdr_dynamic.extend(dyn_tag(0, 0));
    cursor += phdr_dynamic.len();
    let phoff = cursor;
    cursor += 2 * 56;
    let mut file = vec![0u8; cursor];
    file[0..4].copy_from_slice(b"\x7fELF");
    file[4] = 2;
    file[5] = 1;
    file[6] = 1;
    file[16..18].copy_from_slice(&3u16.to_le_bytes());
    file[18..20].copy_from_slice(&183u16.to_le_bytes());
    file[20..24].copy_from_slice(&1u32.to_le_bytes());
    file[32..40].copy_from_slice(&u64::try_from(phoff).unwrap().to_le_bytes());
    file[40..48].copy_from_slice(&u64::try_from(shoff).unwrap().to_le_bytes());
    file[54..56].copy_from_slice(&56u16.to_le_bytes());
    file[56..58].copy_from_slice(&2u16.to_le_bytes());
    file[58..60].copy_from_slice(&(shentsize as u16).to_le_bytes());
    file[60..62].copy_from_slice(&4u16.to_le_bytes());
    write_section(
        &mut file,
        shoff,
        shentsize,
        SectionSpec {
            index: 1,
            kind: 11,
            link: 2,
            offset: sec_dynsym_off,
            size: section_dynsym.len(),
            entry: 24,
        },
    );
    write_section(
        &mut file,
        shoff,
        shentsize,
        SectionSpec {
            index: 2,
            kind: 3,
            link: 0,
            offset: sec_str_off,
            size: section_strings.len(),
            entry: 1,
        },
    );
    write_section(
        &mut file,
        shoff,
        shentsize,
        SectionSpec {
            index: 3,
            kind: 6,
            link: 2,
            offset: sec_dyn_off,
            size: section_dynamic.len(),
            entry: 16,
        },
    );
    file[sec_dynsym_off..sec_dynsym_off + section_dynsym.len()].copy_from_slice(&section_dynsym);
    file[sec_str_off..sec_str_off + section_strings.len()].copy_from_slice(&section_strings);
    file[sec_dyn_off..sec_dyn_off + section_dynamic.len()].copy_from_slice(&section_dynamic);
    file[ph_dynsym_off..ph_dynsym_off + phdr_dynsym.len()].copy_from_slice(&phdr_dynsym);
    file[ph_str_off..ph_str_off + phdr_strings.len()].copy_from_slice(&phdr_strings);
    file[ph_hash_off..ph_hash_off + hash.len()].copy_from_slice(&hash);
    file[ph_dyn_off..ph_dyn_off + phdr_dynamic.len()].copy_from_slice(&phdr_dynamic);
    let filesz = u64::try_from(file.len()).unwrap();
    write_phdr(&mut file, phoff, 1, 4, 0, 0, filesz);
    write_phdr(
        &mut file,
        phoff + 56,
        2,
        4,
        u64::try_from(ph_dyn_off).unwrap(),
        u64::try_from(ph_dyn_off).unwrap(),
        u64::try_from(phdr_dynamic.len()).unwrap(),
    );
    file
}

fn executable_conflict() -> (Vec<u8>, u64) {
    let shoff = 64usize;
    let section_off = shoff + 2 * 64;
    let phdr_off = section_off + 1;
    let phoff = phdr_off + 1;
    let mut file = vec![0u8; phoff + 56];
    file[0..4].copy_from_slice(b"\x7fELF");
    file[4] = 2;
    file[5] = 1;
    file[6] = 1;
    file[16..18].copy_from_slice(&3u16.to_le_bytes());
    file[18..20].copy_from_slice(&183u16.to_le_bytes());
    file[20..24].copy_from_slice(&1u32.to_le_bytes());
    file[32..40].copy_from_slice(&u64::try_from(phoff).unwrap().to_le_bytes());
    file[40..48].copy_from_slice(&u64::try_from(shoff).unwrap().to_le_bytes());
    file[54..56].copy_from_slice(&56u16.to_le_bytes());
    file[56..58].copy_from_slice(&1u16.to_le_bytes());
    file[58..60].copy_from_slice(&64u16.to_le_bytes());
    file[60..62].copy_from_slice(&2u16.to_le_bytes());
    let at = shoff + 64;
    file[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
    file[at + 8..at + 16].copy_from_slice(&6u64.to_le_bytes());
    file[at + 16..at + 24].copy_from_slice(&0x1000u64.to_le_bytes());
    file[at + 24..at + 32].copy_from_slice(&u64::try_from(section_off).unwrap().to_le_bytes());
    file[at + 32..at + 40].copy_from_slice(&1u64.to_le_bytes());
    file[section_off] = 0x90;
    file[phdr_off] = 0xc3;
    write_phdr(
        &mut file,
        phoff,
        1,
        5,
        u64::try_from(phdr_off).unwrap(),
        0x1000,
        1,
    );
    (file, u64::try_from(phdr_off).unwrap())
}

fn write_phdr(
    file: &mut [u8],
    at: usize,
    kind: u32,
    flags: u32,
    offset: u64,
    addr: u64,
    filesz: u64,
) {
    file[at..at + 4].copy_from_slice(&kind.to_le_bytes());
    file[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
    file[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
    file[at + 16..at + 24].copy_from_slice(&addr.to_le_bytes());
    file[at + 32..at + 40].copy_from_slice(&filesz.to_le_bytes());
    file[at + 40..at + 48].copy_from_slice(&filesz.to_le_bytes());
}
