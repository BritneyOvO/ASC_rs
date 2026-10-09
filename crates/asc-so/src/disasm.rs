use iced_x86::Formatter;

use crate::elf::{machine_name, CodeSpan, ElfInfo, EM_386, EM_AARCH64, EM_X86_64};
use crate::{Error, Result};

const MAX_BLOCKS: usize = 4;
const MAX_INSNS: usize = 12;
/// x86 instructions are at most 15 bytes. Looking back this far finds a start
/// that decodes onto the changed byte instead of into the middle of one.
const X86_MAX_INSN: usize = 15;

/// One disassembled window. `left` is empty when the symbol exists only on the right.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisasmBlock {
    pub title: String,
    pub left: Vec<String>,
    pub right: Vec<String>,
}

#[derive(Clone, Copy)]
enum Side {
    Left,
    Right,
}

impl Side {
    fn label(self) -> &'static str {
        match self {
            Self::Left => "export -",
            Self::Right => "export +",
        }
    }
}

/// Disassemble code that actually differs, plus exports that were added or removed.
///
/// Byte differences that sit outside executable sections are ignored. That skips
/// section-header index rewrites and `.shstrtab` reordering. x86 and x86_64 use
/// NASM syntax. AArch64 uses the `disarm64` printer. Other machines produce one
/// note instead of a dump.
pub fn disassemble_changes(
    left_bytes: &[u8],
    right_bytes: &[u8],
    left: &ElfInfo,
    right: &ElfInfo,
) -> Vec<DisasmBlock> {
    let mut blocks = Vec::new();
    let addresses = code_diff_addresses(left_bytes, right_bytes, left, right);
    if let Some(title) = unsupported(left, right) {
        let exports_changed = left.exports != right.exports;
        if exports_changed || !addresses.is_empty() {
            blocks.push(DisasmBlock {
                title,
                left: Vec::new(),
                right: Vec::new(),
            });
        }
        note_address_move(&mut blocks, left, right);
        return blocks;
    }

    let mut covered = Vec::new();
    for name in right.exports.difference(&left.exports) {
        if blocks.len() >= MAX_BLOCKS {
            return blocks;
        }
        if let Err(err) = push_symbol(
            &mut blocks,
            &mut covered,
            right_bytes,
            right,
            name,
            Side::Right,
        ) {
            blocks.push(note(&err));
            return blocks;
        }
    }
    for name in left.exports.difference(&right.exports) {
        if blocks.len() >= MAX_BLOCKS {
            return blocks;
        }
        if let Err(err) = push_symbol(
            &mut blocks,
            &mut covered,
            left_bytes,
            left,
            name,
            Side::Left,
        ) {
            blocks.push(note(&err));
            return blocks;
        }
    }
    for address in addresses {
        if blocks.len() >= MAX_BLOCKS {
            break;
        }
        if covers(&covered, address) {
            continue;
        }
        let left_lines = match disassemble_at(left_bytes, left, address, 0, Align::X86Boundary) {
            Ok(lines) => lines,
            Err(err) => {
                blocks.push(note(&err));
                return blocks;
            }
        };
        let right_lines = match disassemble_at(right_bytes, right, address, 0, Align::X86Boundary) {
            Ok(lines) => lines,
            Err(err) => {
                blocks.push(note(&err));
                return blocks;
            }
        };
        if left_lines.is_empty() && right_lines.is_empty() {
            continue;
        }
        blocks.push(DisasmBlock {
            title: format!("code {address:#x}"),
            left: left_lines,
            right: right_lines,
        });
    }
    note_address_move(&mut blocks, left, right);
    blocks
}

fn note_address_move(blocks: &mut Vec<DisasmBlock>, left: &ElfInfo, right: &ElfInfo) {
    if blocks.len() >= MAX_BLOCKS || same_exec_addresses(&left.code, &right.code) {
        return;
    }
    blocks.push(DisasmBlock {
        title: "executable addresses differ; only overlapping code is disassembled".to_string(),
        left: Vec::new(),
        right: Vec::new(),
    });
}

fn same_exec_addresses(left: &[CodeSpan], right: &[CodeSpan]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut pending: Vec<u64> = right.iter().map(|span| span.address).collect();
    for span in left {
        let Some(pos) = pending.iter().position(|addr| *addr == span.address) else {
            return false;
        };
        pending.remove(pos);
    }
    true
}

fn note(err: &Error) -> DisasmBlock {
    DisasmBlock {
        title: err.to_string(),
        left: Vec::new(),
        right: Vec::new(),
    }
}

fn unsupported(left: &ElfInfo, right: &ElfInfo) -> Option<String> {
    let left_ok = supported(left.machine_id);
    let right_ok = supported(right.machine_id);
    if left_ok && right_ok {
        return None;
    }
    let name = if left.machine == right.machine {
        left.machine.clone()
    } else if !left_ok && !right_ok {
        format!("{} / {}", left.machine, right.machine)
    } else if !left_ok {
        left.machine.clone()
    } else {
        right.machine.clone()
    };
    Some(format!("disassembly is not implemented for {name}"))
}

fn supported(machine: u16) -> bool {
    matches!(machine, EM_386 | EM_X86_64 | EM_AARCH64)
}

fn push_symbol(
    blocks: &mut Vec<DisasmBlock>,
    covered: &mut Vec<(u64, u64)>,
    bytes: &[u8],
    info: &ElfInfo,
    name: &str,
    side: Side,
) -> Result<()> {
    let Some(loc) = info.export_at.get(name) else {
        return Ok(());
    };
    let lines = disassemble_at(bytes, info, loc.address, loc.size, Align::AtAddress)?;
    if lines.is_empty() {
        return Ok(());
    }
    let (left, right) = match side {
        Side::Left => (lines, Vec::new()),
        Side::Right => (Vec::new(), lines),
    };
    blocks.push(DisasmBlock {
        title: format!("{} {name}", side.label()),
        left,
        right,
    });
    covered.push((loc.address, loc.size));
    Ok(())
}

fn covers(ranges: &[(u64, u64)], address: u64) -> bool {
    ranges.iter().any(|&(start, size)| {
        if size == 0 {
            address == start
        } else {
            address >= start && address - start < size
        }
    })
}

fn code_diff_addresses(
    left_bytes: &[u8],
    right_bytes: &[u8],
    left: &ElfInfo,
    right: &ElfInfo,
) -> Vec<u64> {
    let mut addresses = Vec::new();
    for span in &left.code {
        let Some(other) = right.code.iter().find(|item| item.address == span.address) else {
            continue;
        };
        let left_slice = span.slice(left_bytes);
        let right_slice = other.slice(right_bytes);
        let shared = left_slice.len().min(right_slice.len());
        let mut offset = 0usize;
        let mut found = false;
        while offset < shared && addresses.len() < 2 {
            let end = (offset + 4096).min(shared);
            let Some(pos) = first_diff(&left_slice[offset..end], &right_slice[offset..end]) else {
                offset = end;
                continue;
            };
            let at = offset + pos;
            if let Some(address) = add_addr(span.address, at) {
                addresses.push(address);
            }
            found = true;
            offset = at + 16;
        }
        if !found && left_slice.len() != right_slice.len() && addresses.len() < 2 {
            if let Some(address) = add_addr(span.address, shared) {
                addresses.push(address);
            }
        }
    }
    addresses
}

fn first_diff(left: &[u8], right: &[u8]) -> Option<usize> {
    // Slice equality is memcmp, so an unchanged page does not walk each byte.
    if left == right {
        return None;
    }
    left.iter().zip(right).position(|(a, b)| a != b)
}

fn add_addr(base: u64, offset: usize) -> Option<u64> {
    u64::try_from(offset)
        .ok()
        .and_then(|delta| base.checked_add(delta))
}

enum Align {
    AtAddress,
    X86Boundary,
}

fn disassemble_at(
    bytes: &[u8],
    info: &ElfInfo,
    address: u64,
    size: u64,
    align: Align,
) -> Result<Vec<String>> {
    let Some(span) = info
        .code
        .iter()
        .copied()
        .find(|span| span.contains(address))
    else {
        return Ok(Vec::new());
    };
    let whole = span.slice(bytes);
    let entry = match align {
        Align::AtAddress => address,
        Align::X86Boundary => instruction_start(info.machine_id, whole, span.address, address),
    };
    let start = entry.saturating_sub(span.address);
    let file = span.offset.saturating_add(start);
    let available = span.size.saturating_sub(start);
    let want = if size == 0 {
        available
    } else {
        size.min(available)
    };
    let slice = file_slice(bytes, file, want);
    decode(info.machine_id, slice, entry, MAX_INSNS)
}

fn instruction_start(machine: u16, code: &[u8], base: u64, target: u64) -> u64 {
    if !matches!(machine, EM_386 | EM_X86_64) {
        return target;
    }
    let Some(target_off) = target
        .checked_sub(base)
        .and_then(|delta| usize::try_from(delta).ok())
    else {
        return target;
    };
    if target_off > code.len() {
        return target;
    }
    let bitness = if machine == EM_386 { 32 } else { 64 };
    let mut covering = None;
    let window = target_off.min(X86_MAX_INSN);
    for back in 1..=window {
        let start_off = target_off - back;
        let Some(start_addr) = add_addr(base, start_off) else {
            continue;
        };
        let slice = code.get(start_off..).unwrap_or(&[]);
        // A decode that lands on `target` means that byte begins an instruction.
        if x86_reaches(bitness, slice, start_addr, target) {
            return target;
        }
        if covering.is_none() {
            let covered = first_insn_len(bitness, slice, start_addr).is_some_and(|len| {
                let end = start_addr.saturating_add(len);
                start_addr < target && end > target
            });
            if covered {
                covering = Some(start_addr);
            }
        }
    }
    covering.unwrap_or(target)
}

fn first_insn_len(bitness: u32, code: &[u8], start: u64) -> Option<u64> {
    let mut decoder =
        iced_x86::Decoder::with_ip(bitness, code, start, iced_x86::DecoderOptions::NONE);
    let mut instruction = iced_x86::Instruction::default();
    if !decoder.can_decode() {
        return None;
    }
    decoder.decode_out(&mut instruction);
    if instruction.is_invalid() {
        None
    } else {
        u64::try_from(instruction.len()).ok()
    }
}

fn x86_reaches(bitness: u32, code: &[u8], start: u64, target: u64) -> bool {
    let mut decoder =
        iced_x86::Decoder::with_ip(bitness, code, start, iced_x86::DecoderOptions::NONE);
    let mut instruction = iced_x86::Instruction::default();
    for _ in 0..8 {
        if !decoder.can_decode() {
            return false;
        }
        decoder.decode_out(&mut instruction);
        if instruction.is_invalid() {
            return false;
        }
        if instruction.ip() == target {
            return true;
        }
        if instruction.ip() > target {
            return false;
        }
    }
    false
}

fn file_slice(bytes: &[u8], offset: u64, size: u64) -> &[u8] {
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

fn decode(machine: u16, code: &[u8], address: u64, limit: usize) -> Result<Vec<String>> {
    match machine {
        EM_386 => Ok(decode_x86(32, code, address, limit)),
        EM_X86_64 => Ok(decode_x86(64, code, address, limit)),
        EM_AARCH64 => Ok(decode_aarch64(code, address, limit)),
        _ => bail!(
            "disassembly is not implemented for {}",
            machine_name(machine)
        ),
    }
}

fn decode_x86(bitness: u32, code: &[u8], address: u64, limit: usize) -> Vec<String> {
    let mut decoder =
        iced_x86::Decoder::with_ip(bitness, code, address, iced_x86::DecoderOptions::NONE);
    let mut formatter = iced_x86::NasmFormatter::new();
    let mut instruction = iced_x86::Instruction::default();
    let mut text = String::new();
    let mut lines = Vec::new();
    while decoder.can_decode() && lines.len() < limit {
        decoder.decode_out(&mut instruction);
        if instruction.is_invalid() {
            break;
        }
        text.clear();
        formatter.format(&instruction, &mut text);
        lines.push(format!("{:#x}  {text}", instruction.ip()));
    }
    lines
}

fn decode_aarch64(code: &[u8], address: u64, limit: usize) -> Vec<String> {
    let aligned = address & !3;
    let skip = usize::try_from(address - aligned).unwrap_or(0);
    let bytes = code.get(skip..).unwrap_or(&[]);
    let mut lines = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= bytes.len() && lines.len() < limit {
        let word = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        let text = disarm64::decoder::decode(word)
            .map(|insn| insn.to_string())
            .unwrap_or_else(|| ".inst".to_string());
        let ip = aligned.saturating_add(u64::try_from(offset).unwrap_or(0));
        lines.push(format!("{ip:#x}  {text}"));
        offset += 4;
    }
    lines
}

impl CodeSpan {
    fn contains(self, address: u64) -> bool {
        address >= self.address && address - self.address < self.size
    }

    fn slice(self, bytes: &[u8]) -> &[u8] {
        file_slice(bytes, self.offset, self.size)
    }
}
