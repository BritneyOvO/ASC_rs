use asc_hap::{
    dump_abc, dump_hap, find_refs, get_class_source, is_hap, list_classes, load_resources,
    module_json, HapResources, Options, Query,
};

fn options() -> Options {
    Options {
        threads: 2,
        debug: false,
    }
}

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
    let mut buf = vec![0u8; 60];
    buf[..8].copy_from_slice(b"PANDA\0\0\0");
    buf[12] = 2;
    let count_off = buf.len() as u32;
    buf.extend(panda_str("$string:app_name"));
    let main_off = buf.len() as u32;
    buf.extend(panda_str("main"));
    let hello_off = buf.len() as u32;
    buf.extend(panda_str("hello"));
    let label_off = buf.len() as u32;
    buf.extend(panda_str("$string:app_name"));
    let foreign_off = buf.len() as u32;
    buf.extend(panda_str("Lpanda/Object;"));
    let foreign_size = buf.len() as u32 - foreign_off;
    let class_off = buf.len() as u32;
    buf.extend(panda_str("Ldemo/App;"));
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
    let proto_off = buf.len() as u32;
    push_u16(&mut buf, 0x0001);
    let class_idx_off = buf.len() as u32;
    push_u32(&mut buf, class_off);
    push_u32(&mut buf, 0x0005);
    let proto_idx_off = buf.len() as u32;
    push_u32(&mut buf, proto_off);
    let region_off = buf.len() as u32;
    push_u32(&mut buf, class_off);
    push_u32(&mut buf, class_idx_off);
    push_u32(&mut buf, 2);
    push_u32(&mut buf, class_idx_off);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 1);
    push_u32(&mut buf, proto_idx_off);
    let class_index_off = buf.len() as u32;
    push_u32(&mut buf, class_off);
    push_u32(&mut buf, foreign_off);
    let array_off = buf.len() as u32;
    push_u32(&mut buf, 4);
    buf.push(0x05);
    push_u32(&mut buf, hello_off);
    buf.push(0x05);
    push_u32(&mut buf, label_off);
    let literal_idx_off = buf.len() as u32;
    push_u32(&mut buf, array_off);
    let file_size = buf.len() as u32;
    put_u32(&mut buf, 16, file_size);
    put_u32(&mut buf, 20, foreign_off);
    put_u32(&mut buf, 24, foreign_size);
    put_u32(&mut buf, 28, 2);
    put_u32(&mut buf, 32, class_index_off);
    put_u32(&mut buf, 44, 1);
    put_u32(&mut buf, 48, literal_idx_off);
    put_u32(&mut buf, 52, 1);
    put_u32(&mut buf, 56, region_off);
    buf
}

fn zip_stored(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut local = Vec::new();
    let mut central = Vec::new();
    for (name, data) in files {
        let name_bytes = name.as_bytes();
        let offset = local.len() as u32;
        let crc = crc32fast::hash(data);
        local.extend_from_slice(&0x04034b50u32.to_le_bytes());
        local.extend_from_slice(&20u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&(data.len() as u32).to_le_bytes());
        local.extend_from_slice(&(data.len() as u32).to_le_bytes());
        local.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(name_bytes);
        local.extend_from_slice(data);
        central.extend_from_slice(&0x02014b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name_bytes);
    }
    let cd_off = local.len() as u32;
    let cd_size = central.len() as u32;
    let mut out = local;
    out.extend(central);
    out.extend_from_slice(&0x06054b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[test]
fn reads_classes_and_module_json_from_a_hap() {
    let abc = sample_abc();
    let manifest = br#"{"module":{"name":"entry","type":"entry","description":"$string:app_name","icon":"$media:icon"}}"#;
    let strings = br#"{"string":[{"name":"app_name","value":"Hello"}]}"#;
    let pack = br#"{"summary":{"app":{"bundleName":"com.example.hap"}}}"#;
    let hap = zip_stored(&[
        ("js/default.abc", abc.as_slice()),
        ("module.json", manifest),
        ("pack.info", pack),
        ("resources/base/element/string.json", strings),
        (
            "resources/zh_CN/element/string.json",
            br#"{"string":[{"name":"app_name","value":"Nihao"}]}"#,
        ),
        ("resources/base/media/icon.png", b"png"),
        ("ets/modules.abc", abc.as_slice()),
    ]);
    let dir = std::env::temp_dir().join(format!("asc-hap-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("entry.hap");
    std::fs::write(&path, hap).unwrap();
    assert!(is_hap(&path).unwrap());
    let apk_like = dir.join("config-only.apk");
    std::fs::write(
        &apk_like,
        zip_stored(&[("assets/dva_splits/config.json", br#"{"splits":[]}"#)]),
    )
    .unwrap();
    assert!(!is_hap(&apk_like).unwrap());
    let names = list_classes(&path, Some("Ldemo"), &options()).unwrap();
    assert_eq!(
        names,
        vec!["Ldemo/App;".to_string(), "Ldemo/App;".to_string()]
    );
    let text = get_class_source(&path, "demo.App", &options()).unwrap();
    assert!(text.contains("public static void main();"), "{text}");
    assert!(text.contains("public i32 Hello;"), "{text}");
    assert!(!text.contains("$string:"), "{text}");
    let json = module_json(&path).unwrap();
    assert!(json.contains("===== module.json ====="), "{json}");
    assert!(json.contains("\"name\":\"entry\""), "{json}");
    assert!(json.contains("\"description\":\"Hello\""), "{json}");
    assert!(
        json.contains("\"icon\":\"resources/base/media/icon.png\""),
        "{json}"
    );
    assert!(json.contains("===== pack.info ====="), "{json}");
    assert!(json.contains("com.example.hap"), "{json}");
    let lines = find_refs(&path, Query::String("hello"), &options()).unwrap();
    assert!(lines[0].starts_with("ets/modules.abc"), "{lines:?}");
    let labels = find_refs(&path, Query::String("Hello"), &options()).unwrap();
    assert!(
        labels.iter().any(|line| line.contains("matched=(Hello)")),
        "{labels:?}"
    );
    let raw = find_refs(&path, Query::String(r"\$string:app_name"), &options()).unwrap();
    assert!(
        raw.iter().any(|line| line.contains("matched=(Hello)")),
        "{raw:?}"
    );
    let out = dir.join("out");
    let stats = dump_hap(&path, &out, &options()).unwrap();
    assert_eq!(stats.classes, 4);
    assert!(out.join("module.json").is_file());
    assert!(std::fs::read_to_string(out.join("pack.info"))
        .unwrap()
        .contains("com.example.hap"));
    assert!(out.join("demo/App.ets").is_file());
    let dumped = std::fs::read_to_string(out.join("demo/App.ets")).unwrap();
    assert!(dumped.contains("public i32 Hello;"), "{dumped}");

    let bare = dir.join("modules.abc");
    std::fs::write(&bare, &abc).unwrap();
    let raw = asc_abc::class_text(&abc, "demo.App").unwrap();
    assert!(raw.contains("$string:app_name"), "{raw}");
    let resource_dir = dir.join("resroot");
    std::fs::create_dir_all(resource_dir.join("base/element")).unwrap();
    std::fs::write(
        resource_dir.join("base/element/string.json"),
        strings,
    )
    .unwrap();
    let external = load_resources(&resource_dir).unwrap();
    let filled = external.annotate(&raw);
    assert!(filled.contains("Hello"), "{filled}");
    assert!(!filled.contains("$string:"), "{filled}");
    let bare_out = dir.join("bare-out");
    let stats = dump_abc(&abc, &bare_out, &external).unwrap();
    assert_eq!(stats.classes, 2);
    assert!(std::fs::read_to_string(bare_out.join("demo/App.ets"))
        .unwrap()
        .contains("Hello"));
    let untouched = dump_abc(&abc, &dir.join("raw-out"), &HapResources::default()).unwrap();
    assert_eq!(untouched.classes, 2);
    assert!(std::fs::read_to_string(dir.join("raw-out/demo/App.ets"))
        .unwrap()
        .contains("$string:app_name"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_dump_keeps_the_members_it_can_read() {
    let abc = sample_abc();
    let hap = zip_stored(&[
        ("module.json", br#"{"module":{"name":"entry"}}"#),
        ("pack.info", br#"{}"#),
        ("ets/modules.abc", abc.as_slice()),
        ("libs/broken.abc", b"NOT-AN-ABC-FILE"),
    ]);
    let dir = std::env::temp_dir().join(format!("asc-hap-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("entry.hap");
    std::fs::write(&path, hap).unwrap();
    let stats = dump_hap(&path, &dir.join("out"), &options()).unwrap();
    // The readable member is still written, and the broken one is counted
    // rather than ending the dump.
    assert!(stats.classes >= 1, "{stats:?}");
    assert!(stats.errors >= 1, "{stats:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
