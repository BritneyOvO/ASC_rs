use crate::Result;

pub fn u16_at(data: &[u8], off: usize) -> Result<u16> {
    let bytes = data
        .get(off..off + 2)
        .ok_or_else(|| crate::Error::new(format!("truncated read at {off:#x}")))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

pub fn u32_at(data: &[u8], off: usize) -> Result<u32> {
    let bytes = data
        .get(off..off + 4)
        .ok_or_else(|| crate::Error::new(format!("truncated read at {off:#x}")))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub fn read_uleb(data: &[u8], pos: usize) -> Result<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift = 0;
    for i in 0..5 {
        let byte = *data
            .get(pos + i)
            .ok_or_else(|| crate::Error::new("truncated uleb128"))?;
        result |= u32::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }
    bail!("uleb128 is too long");
}

pub fn uleb_len(data: &[u8], pos: usize) -> Result<usize> {
    for i in 0..5 {
        let byte = *data
            .get(pos + i)
            .ok_or_else(|| crate::Error::new("truncated uleb128"))?;
        if byte < 0x80 {
            return Ok(i + 1);
        }
    }
    let mut p = pos + 5;
    while data.get(p).copied().unwrap_or(0) >= 0x80 {
        p += 1;
        if p - pos > 8 {
            bail!("uleb128 is too long");
        }
    }
    if p >= data.len() {
        bail!("truncated uleb128");
    }
    Ok(p - pos + 1)
}

/// Decode a DEX Modified UTF-8 payload (no trailing NUL).
pub fn decode_mutf8(bytes: &[u8]) -> String {
    let mut units = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let a = bytes[i];
        if a == 0 {
            break;
        }
        if a < 0x80 {
            units.push(u16::from(a));
            i += 1;
        } else if a & 0xe0 == 0xc0 && i + 1 < bytes.len() {
            let b = bytes[i + 1];
            units.push(((u16::from(a) & 0x1f) << 6) | (u16::from(b) & 0x3f));
            i += 2;
        } else if a & 0xf0 == 0xe0 && i + 2 < bytes.len() {
            let b = bytes[i + 1];
            let c = bytes[i + 2];
            units.push(
                ((u16::from(a) & 0x0f) << 12)
                    | ((u16::from(b) & 0x3f) << 6)
                    | (u16::from(c) & 0x3f),
            );
            i += 3;
        } else {
            units.push(0xfffd);
            i += 1;
        }
    }
    String::from_utf16_lossy(&units)
}

pub fn read_until_nul(data: &[u8], start: usize) -> Result<&[u8]> {
    let rest = data
        .get(start..)
        .ok_or_else(|| crate::Error::new("bad string_data_off"))?;
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| crate::Error::new("unterminated string_data_item"))?;
    Ok(&rest[..end])
}
