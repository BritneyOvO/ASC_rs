//! Class-definition probes that read only the header, id tables, and string data.

use crate::bytes::{u32_at, uleb_len};
use crate::Result;

const HEADER_SIZE: usize = 0x70;

fn string_data_bytes(buf: &[u8], str_off: usize) -> Result<&[u8]> {
    let ptr = str_off + uleb_len(buf, str_off)?;
    let rest = buf
        .get(ptr..)
        .ok_or_else(|| crate::Error::new("truncated DEX string"))?;
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| crate::Error::new("unterminated DEX string"))?;
    Ok(&rest[..end])
}

/// Binary search the type table for `target` (raw descriptor bytes).
pub fn find_type_idx(buf: &[u8], target: &[u8]) -> Result<Option<u32>> {
    if buf.len() < HEADER_SIZE || &buf[..4] != b"dex\n" {
        return Ok(None);
    }
    let string_ids_size = usize::try_from(u32_at(buf, 0x38)?).unwrap_or(usize::MAX);
    let string_ids_off = usize::try_from(u32_at(buf, 0x3c)?).unwrap_or(usize::MAX);
    let type_ids_size = usize::try_from(u32_at(buf, 0x40)?).unwrap_or(usize::MAX);
    let type_ids_off = usize::try_from(u32_at(buf, 0x44)?).unwrap_or(usize::MAX);
    if string_ids_size == 0 || type_ids_size == 0 {
        return Ok(None);
    }
    if string_ids_off.saturating_add(string_ids_size.saturating_mul(4)) > buf.len()
        || type_ids_off.saturating_add(type_ids_size.saturating_mul(4)) > buf.len()
    {
        bail!("DEX id table is outside the buffer");
    }
    let mut left = 0i64;
    let mut right = type_ids_size as i64 - 1;
    while left <= right {
        let mid = ((left + right) >> 1) as usize;
        let str_idx = usize::try_from(u32_at(buf, type_ids_off + mid * 4)?).unwrap_or(usize::MAX);
        if str_idx >= string_ids_size {
            bail!("type_id string index is out of range");
        }
        let str_off = usize::try_from(u32_at(buf, string_ids_off + str_idx * 4)?).unwrap_or(0);
        let class_name = string_data_bytes(buf, str_off)?;
        match class_name.cmp(target) {
            std::cmp::Ordering::Equal => {
                return Ok(u32::try_from(mid).ok());
            }
            std::cmp::Ordering::Less => left = mid as i64 + 1,
            std::cmp::Ordering::Greater => right = mid as i64 - 1,
        }
    }
    Ok(None)
}

/// Whether any `class_def_item` uses `type_idx`.
pub fn class_defs_contain_type_idx(buf: &[u8], type_idx: u32) -> Result<bool> {
    let size = usize::try_from(u32_at(buf, 0x60)?).unwrap_or(0);
    let off = usize::try_from(u32_at(buf, 0x64)?).unwrap_or(0);
    if size == 0 {
        return Ok(false);
    }
    let end = off.saturating_add(size.saturating_mul(32));
    if end > buf.len() {
        bail!("class_defs run past the buffer");
    }
    let needle = type_idx.to_le_bytes();
    Ok(buf[off..end].chunks_exact(32).any(|item| item[..4] == needle))
}

/// Whether this buffer defines `target` (`Lcom/example/Main;`), not merely references it.
pub fn dex_defines_class(buf: &[u8], target: &[u8]) -> Result<bool> {
    match find_type_idx(buf, target)? {
        Some(idx) => class_defs_contain_type_idx(buf, idx),
        None => Ok(false),
    }
}

/// Leading bytes a class probe needs: id tables plus the start of every string.
///
/// `None` when the prefix does not yet contain the header and those tables.
/// The caller should read a little past this offset so the last string's bytes
/// are present.
pub fn probe_needed_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < HEADER_SIZE || &buf[..4] != b"dex\n" {
        return None;
    }
    let string_ids_size = u32_at(buf, 0x38).ok()? as usize;
    let string_ids_off = u32_at(buf, 0x3c).ok()? as usize;
    let type_ids_size = u32_at(buf, 0x40).ok()? as usize;
    let type_ids_off = u32_at(buf, 0x44).ok()? as usize;
    let class_defs_size = u32_at(buf, 0x60).ok()? as usize;
    let class_defs_off = u32_at(buf, 0x64).ok()? as usize;
    let string_ids_end = string_ids_off.checked_add(string_ids_size.checked_mul(4)?)?;
    let type_ids_end = type_ids_off.checked_add(type_ids_size.checked_mul(4)?)?;
    let class_defs_end = class_defs_off.checked_add(class_defs_size.checked_mul(32)?)?;
    let tables_end = string_ids_end.max(type_ids_end).max(class_defs_end);
    if tables_end > buf.len() {
        return None;
    }
    let mut needed = tables_end;
    for index in 0..string_ids_size {
        let off = u32_at(buf, string_ids_off + index * 4).ok()? as usize;
        needed = needed.max(off);
    }
    Some(needed)
}
