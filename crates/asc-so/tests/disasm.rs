use asc_so::{disassemble_changes, ElfInfo};

fn x86_function(machine: u16, class: u8, symbol: &str, code: &[u8]) -> Vec<u8> {
    x86_at(machine, class, symbol, 0x1000, code)
}

fn x86_at(machine: u16, class: u8, symbol: &str, addr: u64, code: &[u8]) -> Vec<u8> {
    let is_64 = class == 2;
    let header = if is_64 { 64 } else { 52 };
    let shentsize = if is_64 { 64 } else { 40 };
    let shoff = header;
    let shnum = 4;
    let sections = shoff + shnum * shentsize;
    let text_off = sections;
    let sym_off = text_off + code.len();
    let str_off = sym_off + if is_64 { 48 } else { 32 };
    let mut strings = vec![0];
    strings.extend_from_slice(symbol.as_bytes());
    strings.push(0);
    let mut file = vec![0u8; str_off + strings.len()];
    file[0..4].copy_from_slice(b"\x7fELF");
    file[4] = class;
    file[5] = 1;
    file[6] = 1;
    file[16..18].copy_from_slice(&3u16.to_le_bytes());
    file[18..20].copy_from_slice(&machine.to_le_bytes());
    file[20..24].copy_from_slice(&1u32.to_le_bytes());
    if is_64 {
        file[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
        file[52..54].copy_from_slice(&64u16.to_le_bytes());
        file[58..60].copy_from_slice(&(shentsize as u16).to_le_bytes());
        file[60..62].copy_from_slice(&(shnum as u16).to_le_bytes());
        write_sh64(
            &mut file,
            shoff,
            1,
            section(1, 6, text_off, code.len(), addr),
        );
        write_sh64(&mut file, shoff, 2, section(11, 3, sym_off, 48, 0));
        write_sh64(
            &mut file,
            shoff,
            3,
            section(3, 0, str_off, strings.len(), 0),
        );
        file[sym_off + 24..sym_off + 28].copy_from_slice(&1u32.to_le_bytes());
        file[sym_off + 28] = 0x12;
        file[sym_off + 30..sym_off + 32].copy_from_slice(&1u16.to_le_bytes());
        file[sym_off + 32..sym_off + 40].copy_from_slice(&addr.to_le_bytes());
        file[sym_off + 40..sym_off + 48].copy_from_slice(&(code.len() as u64).to_le_bytes());
    } else {
        file[32..36].copy_from_slice(&(shoff as u32).to_le_bytes());
        file[40..42].copy_from_slice(&52u16.to_le_bytes());
        file[46..48].copy_from_slice(&(shentsize as u16).to_le_bytes());
        file[48..50].copy_from_slice(&(shnum as u16).to_le_bytes());
        write_sh32(
            &mut file,
            shoff,
            1,
            section(1, 6, text_off, code.len(), addr),
        );
        write_sh32(&mut file, shoff, 2, section(11, 3, sym_off, 32, 0));
        write_sh32(
            &mut file,
            shoff,
            3,
            section(3, 0, str_off, strings.len(), 0),
        );
        file[sym_off + 16..sym_off + 20].copy_from_slice(&1u32.to_le_bytes());
        file[sym_off + 20..sym_off + 24]
            .copy_from_slice(&u32::try_from(addr).unwrap().to_le_bytes());
        file[sym_off + 24..sym_off + 28].copy_from_slice(&(code.len() as u32).to_le_bytes());
        file[sym_off + 28] = 0x12;
        file[sym_off + 30..sym_off + 32].copy_from_slice(&1u16.to_le_bytes());
    }
    file[text_off..text_off + code.len()].copy_from_slice(code);
    file[str_off..str_off + strings.len()].copy_from_slice(&strings);
    file
}

struct Section {
    kind: u32,
    flags: u64,
    offset: usize,
    size: usize,
    addr: u64,
}

fn section(kind: u32, flags: u64, offset: usize, size: usize, addr: u64) -> Section {
    Section {
        kind,
        flags,
        offset,
        size,
        addr,
    }
}

fn write_sh64(file: &mut [u8], shoff: usize, index: usize, section: Section) {
    let at = shoff + index * 64;
    file[at + 4..at + 8].copy_from_slice(&section.kind.to_le_bytes());
    file[at + 8..at + 16].copy_from_slice(&section.flags.to_le_bytes());
    file[at + 16..at + 24].copy_from_slice(&section.addr.to_le_bytes());
    file[at + 24..at + 32].copy_from_slice(&u64::try_from(section.offset).unwrap().to_le_bytes());
    file[at + 32..at + 40].copy_from_slice(&u64::try_from(section.size).unwrap().to_le_bytes());
    file[at + 40..at + 44].copy_from_slice(&3u32.to_le_bytes());
    file[at + 56..at + 64]
        .copy_from_slice(&if section.kind == 11 { 24u64 } else { 1 }.to_le_bytes());
}

fn write_sh32(file: &mut [u8], shoff: usize, index: usize, section: Section) {
    let at = shoff + index * 40;
    file[at + 4..at + 8].copy_from_slice(&section.kind.to_le_bytes());
    file[at + 8..at + 12].copy_from_slice(&u32::try_from(section.flags).unwrap().to_le_bytes());
    file[at + 12..at + 16].copy_from_slice(&u32::try_from(section.addr).unwrap().to_le_bytes());
    file[at + 16..at + 20].copy_from_slice(&u32::try_from(section.offset).unwrap().to_le_bytes());
    file[at + 20..at + 24].copy_from_slice(&u32::try_from(section.size).unwrap().to_le_bytes());
    file[at + 24..at + 28].copy_from_slice(&3u32.to_le_bytes());
    file[at + 36..at + 40]
        .copy_from_slice(&if section.kind == 11 { 16u32 } else { 1 }.to_le_bytes());
}

#[test]
fn x86_and_x86_64_code_changes_are_disassembled() {
    let left_bytes = x86_function(3, 1, "work", &[0x90, 0xc3]);
    let right_bytes = x86_function(3, 1, "work", &[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]);
    let left = ElfInfo::parse(&left_bytes).unwrap();
    let right = ElfInfo::parse(&right_bytes).unwrap();
    let blocks = disassemble_changes(&left_bytes, &right_bytes, &left, &right);
    let text = format!("{blocks:?}");
    assert!(text.contains("nop"), "{text}");
    assert!(text.contains("mov"), "{text}");

    let left64 = x86_function(62, 2, "work", &[0x90, 0xc3]);
    let right64 = x86_function(62, 2, "work", &[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]);
    let info_l = ElfInfo::parse(&left64).unwrap();
    let info_r = ElfInfo::parse(&right64).unwrap();
    let blocks = disassemble_changes(&left64, &right64, &info_l, &info_r);
    let text = format!("{blocks:?}");
    assert!(text.contains("nop"), "{text}");
    assert!(text.contains("mov"), "{text}");
}

#[test]
fn aarch64_code_changes_are_disassembled() {
    // nop; ret  versus  mov x0, #1; ret
    let left_code = [0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6];
    let right_code = [0x20, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6];
    let left = x86_function(183, 2, "work", &left_code);
    let right = x86_function(183, 2, "work", &right_code);
    let blocks = disassemble_changes(
        &left,
        &right,
        &ElfInfo::parse(&left).unwrap(),
        &ElfInfo::parse(&right).unwrap(),
    );
    let text = format!("{blocks:?}");
    assert!(text.contains("nop"), "{text}");
    assert!(text.contains("ret"), "{text}");
}

#[test]
fn moved_executable_address_is_reported_without_a_dump() {
    let code = [0x90, 0xc3];
    let left = x86_at(3, 1, "work", 0x1000, &code);
    let right = x86_at(3, 1, "work", 0x2000, &code);
    let blocks = disassemble_changes(
        &left,
        &right,
        &ElfInfo::parse(&left).unwrap(),
        &ElfInfo::parse(&right).unwrap(),
    );
    assert!(
        blocks
            .iter()
            .any(|block| block.title.contains("executable addresses differ")),
        "{blocks:?}"
    );
    assert!(
        blocks.iter().all(|block| !block.title.starts_with("code ")),
        "{blocks:?}"
    );
}

#[test]
fn removed_x86_export_is_disassembled_on_the_left() {
    let code = [0x90, 0xc3];
    let left = x86_function(3, 1, "old", &code);
    let right = x86_function(3, 1, "new", &code);
    let blocks = disassemble_changes(
        &left,
        &right,
        &ElfInfo::parse(&left).unwrap(),
        &ElfInfo::parse(&right).unwrap(),
    );
    let removed = blocks
        .iter()
        .find(|block| block.title == "export - old")
        .unwrap();
    assert!(
        removed.left.iter().any(|line| line.contains("nop")),
        "{removed:?}"
    );
    assert!(removed.right.is_empty(), "{removed:?}");
    let added = blocks
        .iter()
        .find(|block| block.title == "export + new")
        .unwrap();
    assert!(
        added.right.iter().any(|line| line.contains("nop")),
        "{added:?}"
    );
    assert!(added.left.is_empty(), "{added:?}");
}

#[test]
fn bytes_outside_executable_sections_are_not_disassembled() {
    let left = x86_function(62, 2, "work", &[0x90, 0xc3]);
    let mut right = left.clone();
    right.push(0x5a);
    let blocks = disassemble_changes(
        &left,
        &right,
        &ElfInfo::parse(&left).unwrap(),
        &ElfInfo::parse(&right).unwrap(),
    );
    assert!(blocks.is_empty(), "{blocks:?}");
}

#[test]
fn arm_code_changes_report_that_disassembly_is_unavailable() {
    let left = x86_function(40, 1, "work", &[0x00, 0x00, 0xa0, 0xe1]);
    let right = x86_function(40, 1, "work", &[0x01, 0x00, 0xa0, 0xe3]);
    let blocks = disassemble_changes(
        &left,
        &right,
        &ElfInfo::parse(&left).unwrap(),
        &ElfInfo::parse(&right).unwrap(),
    );
    assert_eq!(blocks.len(), 1, "{blocks:?}");
    assert!(blocks[0].title.contains("ARM"), "{blocks:?}");
    assert!(blocks[0].left.is_empty() && blocks[0].right.is_empty());
}
