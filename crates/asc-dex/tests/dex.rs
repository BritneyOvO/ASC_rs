use asc_dex::Dex;

#[test]
fn huge_encoded_array_does_not_allocate() {
    let mut data = vec![0u8; 0x78];
    data[..8].copy_from_slice(b"dex\n035\0");
    data[0x70..0x75].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x0f]);
    let dex = Dex::parse(&data).unwrap();
    let err = dex.static_literals(0x70).unwrap_err();
    assert!(err.to_string().contains("count"), "{err}");
}

/// `[size=1, VALUE_ARRAY]` repeated, then a `VALUE_NULL` leaf.
fn nested_encoded_array(levels: usize) -> (Vec<u8>, u32) {
    let mut data = vec![0u8; 0x70];
    data[..8].copy_from_slice(b"dex\n035\0");
    let start = data.len() as u32;
    for _ in 0..levels {
        data.extend_from_slice(&[0x01, 0x1c]);
    }
    data.extend_from_slice(&[0x01, 0x1e]);
    (data, start)
}

#[test]
fn deep_encoded_values_stop_instead_of_overflowing_the_stack() {
    let (data, start) = nested_encoded_array(4096);
    let dex = Dex::parse(&data).unwrap();
    let err = dex.static_literals(start).unwrap_err();
    assert!(err.to_string().contains("nesting"), "{err}");
}

#[test]
fn a_shallow_encoded_array_still_decodes() {
    let (data, start) = nested_encoded_array(3);
    let dex = Dex::parse(&data).unwrap();
    let values = dex.static_literals(start).unwrap();
    assert_eq!(values, vec!["{{{null}}}".to_string()]);
}
