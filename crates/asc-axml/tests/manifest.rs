use asc_axml::manifest_xml;

fn push_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_le_bytes());
}
fn push_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn encode_utf8_string(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(value.chars().count() as u8);
    out.push(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
    out.push(0);
    out
}

fn encode_pool(strings: &[&str]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    for value in strings {
        offsets.push(data.len() as u32);
        data.extend(encode_utf8_string(value));
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }
    let strings_start = 28 + strings.len() as u32 * 4;
    let mut buf = Vec::new();
    push_u16(&mut buf, 0x0001);
    push_u16(&mut buf, 28);
    push_u32(&mut buf, strings_start + data.len() as u32);
    push_u32(&mut buf, strings.len() as u32);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 1 << 8);
    push_u32(&mut buf, strings_start);
    push_u32(&mut buf, 0);
    for offset in offsets {
        push_u32(&mut buf, offset);
    }
    buf.extend_from_slice(&data);
    buf
}

fn namespace(kind: u16, prefix: u32, uri: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u16(&mut buf, kind);
    push_u16(&mut buf, 16);
    push_u32(&mut buf, 24);
    push_u32(&mut buf, 1);
    push_u32(&mut buf, 0xffff_ffff);
    push_u32(&mut buf, prefix);
    push_u32(&mut buf, uri);
    buf
}

fn element(ns: u32, name: u32, attrs: &[(u32, u32, u32)]) -> Vec<u8> {
    let size = 16 + 20 + attrs.len() * 20;
    let mut buf = Vec::new();
    push_u16(&mut buf, 0x0102);
    push_u16(&mut buf, 16);
    push_u32(&mut buf, size as u32);
    push_u32(&mut buf, 1);
    push_u32(&mut buf, 0xffff_ffff);
    push_u32(&mut buf, ns);
    push_u32(&mut buf, name);
    push_u16(&mut buf, 20);
    push_u16(&mut buf, 20);
    push_u16(&mut buf, attrs.len() as u16);
    push_u16(&mut buf, 0);
    push_u16(&mut buf, 0);
    push_u16(&mut buf, 0);
    for (ans, aname, raw) in attrs {
        push_u32(&mut buf, *ans);
        push_u32(&mut buf, *aname);
        push_u32(&mut buf, *raw);
        push_u16(&mut buf, 8);
        buf.push(0);
        buf.push(0x03);
        push_u32(&mut buf, *raw);
    }
    buf
}

fn end_element(ns: u32, name: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u16(&mut buf, 0x0103);
    push_u16(&mut buf, 16);
    push_u32(&mut buf, 24);
    push_u32(&mut buf, 1);
    push_u32(&mut buf, 0xffff_ffff);
    push_u32(&mut buf, ns);
    push_u32(&mut buf, name);
    buf
}

#[test]
fn decodes_a_small_manifest() {
    let strings = [
        "android",
        "http://schemas.android.com/apk/res/android",
        "manifest",
        "package",
        "com.example",
        "application",
        "label",
        "Demo",
    ];
    let mut body = encode_pool(&strings);
    body.extend(namespace(0x0100, 0, 1));
    body.extend(element(0xffff_ffff, 2, &[(0xffff_ffff, 3, 4)]));
    body.extend(element(0xffff_ffff, 5, &[(1, 6, 7)]));
    body.extend(end_element(0xffff_ffff, 5));
    body.extend(end_element(0xffff_ffff, 2));
    body.extend(namespace(0x0101, 0, 1));
    let mut file = Vec::new();
    push_u16(&mut file, 0x0003);
    push_u16(&mut file, 8);
    push_u32(&mut file, (8 + body.len()) as u32);
    file.extend(body);
    let xml = manifest_xml(&file).unwrap();
    assert!(xml.contains("package=\"com.example\""), "{xml}");
    assert!(xml.contains("android:label=\"Demo\""), "{xml}");
    assert!(
        xml.contains("xmlns:android=\"http://schemas.android.com/apk/res/android\""),
        "{xml}"
    );
}

#[test]
fn an_obfuscated_framework_attribute_uses_its_resource_id() {
    let strings = ["manifest", "a"];
    let mut body = encode_pool(&strings);
    let mut map = Vec::new();
    push_u16(&mut map, 0x0180);
    push_u16(&mut map, 8);
    push_u32(&mut map, 16);
    push_u32(&mut map, 0);
    push_u32(&mut map, 0x0101_0003);
    body.extend(map);
    body.extend(element(0xffff_ffff, 0, &[(0xffff_ffff, 1, 1)]));
    body.extend(end_element(0xffff_ffff, 0));
    let mut file = Vec::new();
    push_u16(&mut file, 0x0003);
    push_u16(&mut file, 8);
    push_u32(&mut file, (8 + body.len()) as u32);
    file.extend(body);
    let xml = manifest_xml(&file).unwrap();
    assert!(xml.contains("name=\"a\""), "{xml}");
    assert!(!xml.contains("a=\"a\""), "{xml}");
}

fn cdata(raw: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u16(&mut buf, 0x0104);
    push_u16(&mut buf, 16);
    push_u32(&mut buf, 28);
    push_u32(&mut buf, 1);
    push_u32(&mut buf, 0xffff_ffff);
    push_u32(&mut buf, raw);
    buf
}

#[test]
fn text_nodes_are_escaped_once() {
    let strings = ["manifest", "A&B"];
    let mut body = encode_pool(&strings);
    body.extend(element(0xffff_ffff, 0, &[]));
    body.extend(cdata(1));
    body.extend(end_element(0xffff_ffff, 0));
    let mut file = Vec::new();
    push_u16(&mut file, 0x0003);
    push_u16(&mut file, 8);
    push_u32(&mut file, (8 + body.len()) as u32);
    file.extend(body);
    let xml = manifest_xml(&file).unwrap();
    assert!(xml.contains("A&amp;B"), "{xml}");
    assert!(!xml.contains("A&amp;amp;B"), "{xml}");
}

fn proto_bytes(field: u32, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let key = u64::from(field) << 3 | 2;
    write_varint(&mut out, key);
    write_varint(&mut out, value.len() as u64);
    out.extend_from_slice(value);
    out
}

fn proto_str(field: u32, value: &str) -> Vec<u8> {
    proto_bytes(field, value.as_bytes())
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
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
}

#[test]
fn decodes_protobuf_manifest() {
    let mut namespace = proto_str(1, "android");
    namespace.extend(proto_str(2, "http://schemas.android.com/apk/res/android"));
    let mut package = proto_str(2, "package");
    package.extend(proto_str(3, "com.example"));
    let reference = proto_str(3, "mipmap/ic_launcher");
    let icon_item = proto_bytes(1, &reference);
    let mut icon = proto_str(1, "http://schemas.android.com/apk/res/android");
    icon.extend(proto_str(2, "icon"));
    icon.extend(proto_bytes(6, &icon_item));
    let mut boolean = Vec::new();
    write_varint(&mut boolean, 8 << 3);
    write_varint(&mut boolean, 1);
    let primitive = proto_bytes(7, &boolean);
    let mut backup = proto_str(1, "http://schemas.android.com/apk/res/android");
    backup.extend(proto_str(2, "allowBackup"));
    backup.extend(proto_bytes(6, &primitive));
    let mut application = proto_str(3, "application");
    application.extend(proto_bytes(4, &icon));
    application.extend(proto_bytes(4, &backup));
    let application = proto_bytes(1, &application);
    let mut manifest = proto_bytes(1, &namespace);
    manifest.extend(proto_str(3, "manifest"));
    manifest.extend(proto_bytes(4, &package));
    manifest.extend(proto_bytes(5, &application));
    let root = proto_bytes(1, &manifest);
    let xml = manifest_xml(&root).unwrap();
    assert!(
        xml.contains("xmlns:android=\"http://schemas.android.com/apk/res/android\""),
        "{xml}"
    );
    assert!(xml.contains("package=\"com.example\""), "{xml}");
    assert!(
        xml.contains("android:icon=\"@mipmap/ic_launcher\""),
        "{xml}"
    );
    assert!(xml.contains("android:allowBackup=\"true\""), "{xml}");
    assert!(xml.contains("<application"), "{xml}");
}
