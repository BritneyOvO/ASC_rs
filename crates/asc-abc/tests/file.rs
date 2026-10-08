use asc_abc::{
    class_names, class_text, find_members, find_strings, find_strings_resolved, MemberKind,
};

fn uleb(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

fn panda_str(text: &str) -> Vec<u8> {
    let mut out = uleb(((text.len() as u32) << 1) | 1);
    out.extend_from_slice(text.as_bytes());
    out.push(0);
    out
}

fn push_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(buf: &mut [u8], off: usize, value: u32) {
    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn sample_abc() -> Vec<u8> {
    abc_with_class_descriptors(&["Ldemo/App;"])
}

/// A minimal ABC whose header class index lists `names` in the order given,
/// followed by one foreign class. Callers pass the order a real file uses:
/// sorted by descriptor bytes.
fn abc_with_class_descriptors(names: &[&str]) -> Vec<u8> {
    let mut buf = vec![0u8; 60];
    buf[..8].copy_from_slice(b"PANDA\0\0\0");
    buf[12] = 2;
    let count_off = buf.len() as u32;
    buf.extend(panda_str("count"));
    let main_off = buf.len() as u32;
    buf.extend(panda_str("main"));
    let hello_off = buf.len() as u32;
    buf.extend(panda_str("hello"));
    let foreign_off = buf.len() as u32;
    buf.extend(panda_str("Lpanda/Object;"));
    let foreign_size = buf.len() as u32 - foreign_off;
    let mut class_offs = Vec::new();
    for name in names {
        class_offs.push(buf.len() as u32);
        buf.extend(panda_str(name));
        push_u32(&mut buf, foreign_off);
        buf.extend(uleb(1));
        buf.extend(uleb(1));
        buf.extend(uleb(1));
        buf.push(0);
        push_u16(&mut buf, 0);
        push_u16(&mut buf, 1);
        push_u32(&mut buf, count_off);
        buf.extend(uleb(1));
        buf.push(0);
        push_u16(&mut buf, 0);
        push_u16(&mut buf, 0);
        push_u32(&mut buf, main_off);
        buf.extend(uleb(0x0009));
        buf.push(0);
    }
    let proto_off = buf.len() as u32;
    push_u16(&mut buf, 0x0001);
    let type_table_off = buf.len() as u32;
    push_u32(&mut buf, class_offs[0]);
    push_u32(&mut buf, 0x0005);
    let proto_idx_off = buf.len() as u32;
    push_u32(&mut buf, proto_off);
    let region_off = buf.len() as u32;
    push_u32(&mut buf, class_offs[0]);
    push_u32(&mut buf, type_table_off);
    push_u32(&mut buf, 2);
    push_u32(&mut buf, type_table_off);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 1);
    push_u32(&mut buf, proto_idx_off);
    let class_index_off = buf.len() as u32;
    for offset in &class_offs {
        push_u32(&mut buf, *offset);
    }
    push_u32(&mut buf, foreign_off);
    let array_off = buf.len() as u32;
    push_u32(&mut buf, 2);
    buf.push(0x05);
    push_u32(&mut buf, hello_off);
    let literal_idx_off = buf.len() as u32;
    push_u32(&mut buf, array_off);
    let file_size = buf.len() as u32;
    put_u32(&mut buf, 16, file_size);
    put_u32(&mut buf, 20, foreign_off);
    put_u32(&mut buf, 24, foreign_size);
    put_u32(&mut buf, 28, names.len() as u32 + 1);
    put_u32(&mut buf, 32, class_index_off);
    put_u32(&mut buf, 44, 1);
    put_u32(&mut buf, 48, literal_idx_off);
    put_u32(&mut buf, 52, 1);
    put_u32(&mut buf, 56, region_off);
    buf
}

/// One class with a single `main` method that records `INVALID_INDEX` as its
/// proto, the way Ark ES classes do. `with_code` decides whether the method
/// carries a code item, which is where the argument count comes from.
fn abc_with_a_protoless_method(with_code: bool) -> Vec<u8> {
    let mut buf = vec![0u8; 60];
    buf[..8].copy_from_slice(b"PANDA\0\0\0");
    buf[12] = 2;
    let main_off = buf.len() as u32;
    buf.extend(panda_str("main"));
    let foreign_off = buf.len() as u32;
    buf.extend(panda_str("Lpanda/Object;"));
    let foreign_size = buf.len() as u32 - foreign_off;
    // Code item: num_vregs=4, num_args=2, code_size=2, two instruction bytes.
    let code_off = buf.len() as u32;
    buf.extend(uleb(4));
    buf.extend(uleb(2));
    buf.extend(uleb(2));
    buf.extend_from_slice(&[0x0e, 0x00]);
    let class_off = buf.len() as u32;
    buf.extend(panda_str("Ldemo/App;"));
    push_u32(&mut buf, foreign_off);
    buf.extend(uleb(1));
    buf.extend(uleb(0));
    buf.extend(uleb(1));
    buf.push(0);
    push_u16(&mut buf, 0);
    push_u16(&mut buf, 0xffff);
    push_u32(&mut buf, main_off);
    buf.extend(uleb(0x0008));
    if with_code {
        buf.push(0x01);
        push_u32(&mut buf, code_off);
    }
    buf.push(0);
    let type_table_off = buf.len() as u32;
    push_u32(&mut buf, class_off);
    push_u32(&mut buf, 0x0005);
    let region_off = buf.len() as u32;
    push_u32(&mut buf, class_off);
    push_u32(&mut buf, type_table_off);
    push_u32(&mut buf, 2);
    push_u32(&mut buf, type_table_off);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, u32::MAX);
    push_u32(&mut buf, u32::MAX);
    let class_index_off = buf.len() as u32;
    push_u32(&mut buf, class_off);
    push_u32(&mut buf, foreign_off);
    let file_size = buf.len() as u32;
    put_u32(&mut buf, 16, file_size);
    put_u32(&mut buf, 20, foreign_off);
    put_u32(&mut buf, 24, foreign_size);
    put_u32(&mut buf, 28, 2);
    put_u32(&mut buf, 32, class_index_off);
    put_u32(&mut buf, 44, 0);
    put_u32(&mut buf, 48, 0);
    put_u32(&mut buf, 52, 1);
    put_u32(&mut buf, 56, region_off);
    buf
}

#[test]
fn a_prefix_is_read_the_same_way_as_in_an_apk() {
    // Real Ark ES descriptors spell their package with dots, and a dotted
    // prefix has to reach them.
    let data = abc_with_class_descriptors(&["Lcom.example/App;"]);
    for prefix in ["com.example", "Lcom.example", "Lcom/example", "com/example"] {
        assert_eq!(
            class_names(&data, Some(prefix)).unwrap(),
            vec!["Lcom.example/App;".to_string()],
            "{prefix}"
        );
    }
    assert!(class_names(&data, Some("com.other")).unwrap().is_empty());
}

#[test]
fn a_protoless_method_takes_its_signature_from_its_code() {
    let data = abc_with_a_protoless_method(true);
    let text = class_text(&data, "Ldemo/App;").unwrap();
    assert!(text.contains("static any main(any a0, any a1);"), "{text}");
}

#[test]
fn a_protoless_method_without_code_has_no_parameters() {
    let data = abc_with_a_protoless_method(false);
    let text = class_text(&data, "Ldemo/App;").unwrap();
    assert!(text.contains("static any main();"), "{text}");
}

#[test]
fn lists_and_reads_one_class_without_an_index() {
    let data = sample_abc();
    assert_eq!(
        class_names(&data, Some("Ldemo")).unwrap(),
        vec!["Ldemo/App;".to_string()]
    );
    let text = class_text(&data, "demo.App").unwrap();
    assert!(
        text.contains("class Ldemo/App; extends Lpanda/Object;"),
        "{text}"
    );
    assert!(text.contains("public i32 count;"), "{text}");
    assert!(text.contains("public static void main();"), "{text}");
    let strings = find_strings(&data, "app.abc", "hello").unwrap();
    assert_eq!(
        strings,
        vec!["app.abc | literal#0 | matched=(hello)".to_string()]
    );
    let resolved = find_strings_resolved(&data, "app.abc", "Hello", &|bytes| {
        if bytes == b"hello" {
            Some("Hello".to_string())
        } else {
            None
        }
    })
    .unwrap();
    assert_eq!(
        resolved,
        vec!["app.abc | literal#0 | matched=(Hello)".to_string()]
    );
    let methods = find_members(
        &data,
        "app.abc",
        MemberKind::Method,
        "main",
        Some("Ldemo/App;"),
    )
    .unwrap();
    assert_eq!(methods, vec!["app.abc | Ldemo/App;->main".to_string()]);
}

/// A header-only ABC with no classes, so a literal query reaches nothing but
/// the header fields under test.
fn header_only_abc(version: [u8; 4], literal_count: u32, literal_off: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 60];
    buf[..8].copy_from_slice(b"PANDA\0\0\0");
    buf[12..16].copy_from_slice(&version);
    put_u32(&mut buf, 16, 60);
    put_u32(&mut buf, 28, 0);
    put_u32(&mut buf, 32, 0);
    put_u32(&mut buf, 44, literal_count);
    put_u32(&mut buf, 48, literal_off);
    buf
}

#[test]
fn a_newer_abc_reports_that_strings_cannot_be_searched() {
    // Version 13 keeps no literal array index in the header. Returning an
    // empty result here would look like "no match" instead of "unsupported".
    let data = header_only_abc([13, 0, 1, 0], u32::MAX, u32::MAX);
    assert!(matches!(
        find_strings(&data, "app.abc", "hello"),
        Err(asc_abc::Error::Unsupported(_))
    ));
    // An older header that really has no literal arrays stays empty.
    let empty = header_only_abc([12, 0, 2, 0], 0, 0);
    assert_eq!(
        find_strings(&empty, "app.abc", "hello").unwrap(),
        Vec::<String>::new()
    );
    // A count with no index is corruption, not "no arrays".
    let broken = header_only_abc([12, 0, 2, 0], 4, u32::MAX);
    assert!(find_strings(&broken, "app.abc", "hello").is_err());
}

#[test]
fn class_lookup_follows_the_byte_sorted_index() {
    // A real class index is sorted by descriptor bytes, which is not the
    // same as sorting by UTF-16 length first: `L@system.app;` is shorter
    // than `L@ohos.curves;` yet sorts after it.
    let data = abc_with_class_descriptors(&["L@ohos.curves;", "L@system.app;"]);
    for name in ["L@ohos.curves;", "L@system.app;"] {
        let text = class_text(&data, name).unwrap();
        assert!(
            text.contains(&format!("class {name} extends Lpanda/Object;")),
            "{name}: {text}"
        );
    }
}

/// One entry of a hand-built literal array.
enum Lit {
    /// A string with tag 0x05.
    Str,
    /// A non-string entry carrying its tag byte and an inline value.
    Tag(u8),
    /// ARRAY_STRING: one pointer to an out of line `[count][pointers]`
    /// buffer, the way upstream stores it.
    ArrayString(usize),
}

/// Builds an ABC whose single literal array holds `items`, returning the
/// file, the strings a decode should find, and the array's file offset.
fn abc_with_literal(items: &[Lit]) -> (Vec<u8>, Vec<String>, usize) {
    let mut buf = vec![0u8; 60];
    buf[..8].copy_from_slice(b"PANDA\0\0\0");
    buf[12] = 2;
    let mut expected = Vec::new();
    let mut offsets = Vec::new();
    let mut index = 0;
    for item in items {
        let count = match item {
            Lit::ArrayString(n) => *n,
            _ => 1,
        };
        for _ in 0..count {
            if matches!(item, Lit::Str | Lit::ArrayString(_)) {
                let text = format!("lit{index}");
                index += 1;
                offsets.push(buf.len() as u32);
                buf.extend(panda_str(&text));
                expected.push(text);
            }
        }
    }
    let mut payload = Vec::new();
    payload.extend_from_slice(&(items.len() as u32 * 2).to_le_bytes());
    // The ARRAY_STRING buffers are appended after the payload, so their
    // pointers are patched once the payload length is known.
    let mut array_strings: Vec<Vec<u32>> = Vec::new();
    let mut patches: Vec<usize> = Vec::new();
    let mut next = 0;
    for item in items {
        let (tag, count) = match item {
            Lit::Str => (0x05, 1),
            Lit::Tag(tag) => (*tag, 0),
            Lit::ArrayString(n) => (0x15, *n),
        };
        payload.push(tag);
        if tag == 0x15 {
            // A single pointer; the count lives in the pointed-to buffer.
            patches.push(payload.len());
            payload.extend_from_slice(&0u32.to_le_bytes());
            array_strings.push(offsets[next..next + count].to_vec());
            next += count;
            continue;
        }
        for _ in 0..count {
            payload.extend_from_slice(&offsets[next].to_le_bytes());
            next += 1;
        }
        // Only scalar entries carry an inline payload; the pointer tags
        // (STRING, ARRAY_STRING) are already complete. The widths are
        // spelled out independently of `literal_tag_width`, so a change to
        // one has to be made in both places or these tests go red.
        if matches!(item, Lit::Tag(_)) {
            match tag {
                // DOUBLE
                0x04 => payload.extend_from_slice(&0u64.to_le_bytes()),
                // METHODAFFILIATE
                0x09 => payload.extend_from_slice(&0u16.to_le_bytes()),
                // INTEGER_8/TAGVALUE, BOOL, ACCESSOR, BUILTINTYPEINDEX, NULLVALUE
                0x00 | 0x01 | 0x08 | 0x19 | 0xff => payload.push(0),
                // Every 32 bit value and pointer.
                _ => payload.extend_from_slice(&0u32.to_le_bytes()),
            }
        }
    }
    let array_off = buf.len() as u32;
    let payload_at = buf.len();
    buf.extend_from_slice(&payload);
    for (slot, strings) in patches.into_iter().zip(array_strings) {
        let buffer_off = buf.len() as u32;
        put_u32(&mut buf, payload_at + slot, buffer_off);
        buf.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        for offset in strings {
            buf.extend_from_slice(&offset.to_le_bytes());
        }
    }
    let literal_idx_off = buf.len() as u32;
    buf.extend_from_slice(&array_off.to_le_bytes());
    let file_size = buf.len() as u32;
    put_u32(&mut buf, 16, file_size);
    put_u32(&mut buf, 44, 1);
    put_u32(&mut buf, 48, literal_idx_off);
    put_u32(&mut buf, 52, 1);
    put_u32(&mut buf, 56, 0);
    (buf, expected, array_off as usize)
}

fn found_literals(data: &[u8]) -> Vec<String> {
    find_strings(data, "app.abc", "lit").unwrap()
}

#[test]
fn literal_arrays_keep_every_string_the_tags_allow() {
    // A string, then a double and a bool, then another string: the walk
    // must not stop at the non-string tags.
    let (data, expected, _) = abc_with_literal(&[
        Lit::Str,
        Lit::Tag(0x04),
        Lit::Tag(0x01),
        Lit::Str,
    ]);
    let found = found_literals(&data);
    assert_eq!(found.len(), 2, "{found:?}");
    for text in &expected {
        assert!(found.iter().any(|line| line.contains(text)), "{text} {found:?}");
    }
}

#[test]
fn tagvalue_is_an_int8_and_never_yields_a_string() {
    // TAGVALUE (0x00) aliases INTEGER_8. `EnumerateLiteralVals` has no case
    // for it and the disassembler drops it, so it is a one byte value, not
    // a string pointer. The array still walks past it to later entries.
    let (data, expected, _) = abc_with_literal(&[Lit::Tag(0x00), Lit::Str]);
    let found = found_literals(&data);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains(&expected[0]), "{found:?}");
}

#[test]
fn pointer_valued_neighbours_are_not_decoded_as_strings() {
    // METHOD, GETTER and SETTER carry a pointer too, but not to string
    // data, so they are skipped rather than decoded as one.
    for tag in [0x06u8, 0x1a, 0x1b] {
        let (mut data, _, array) = abc_with_literal(&[Lit::Tag(tag)]);
        // Even a pointer that would read happily as a string is ignored.
        let pointer_at = array + 4 + 1;
        data[pointer_at..pointer_at + 4].copy_from_slice(&60u32.to_le_bytes());
        let found = found_literals(&data);
        assert!(found.is_empty(), "{tag:#x}: {found:?}");
    }
}

#[test]
fn a_string_entry_with_a_broken_pointer_is_an_error() {
    // A STRING entry must address a string; a pointer to something else is
    // reported instead of being trusted.
    let (mut data, _, array) = abc_with_literal(&[Lit::Str]);
    let pointer_at = array + 4 + 1;
    data[pointer_at..pointer_at + 4].copy_from_slice(&0u32.to_le_bytes());
    let err = find_strings(&data, "app.abc", "lit").unwrap_err();
    assert!(
        err.to_string().contains("not tagged as a string"),
        "{err}"
    );
}

#[test]
fn array_string_keeps_every_element() {
    let (data, expected, _) = abc_with_literal(&[Lit::ArrayString(3)]);
    let found = found_literals(&data);
    assert_eq!(found.len(), 3, "{found:?}");
    for text in &expected {
        assert!(found.iter().any(|line| line.contains(text)), "{text} {found:?}");
    }
}

#[test]
fn typed_arrays_end_the_walk_without_losing_earlier_strings() {
    // A non-string typed array ends the array; the string before it stays.
    let (data, expected, _) = abc_with_literal(&[Lit::Str, Lit::Tag(0x0a)]);
    let found = found_literals(&data);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains(&expected[0]), "{found:?}");
}

#[test]
fn an_unknown_tag_stops_the_walk_without_dropping_earlier_strings() {
    let (data, expected, _) = abc_with_literal(&[Lit::Str, Lit::Tag(0x20)]);
    let found = found_literals(&data);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains(&expected[0]), "{found:?}");
}
