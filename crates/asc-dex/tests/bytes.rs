use asc_dex::bytes::read_uleb;

#[test]
fn uleb_reads_u32_max() {
    let data = [0xff, 0xff, 0xff, 0xff, 0x0f];
    assert_eq!(read_uleb(&data, 0).unwrap(), (u32::MAX, 5));
}

#[test]
fn uleb_rejects_overflowing_fifth_byte() {
    let data = [0x80, 0x80, 0x80, 0x80, 0x7f];
    let err = read_uleb(&data, 0).unwrap_err();
    assert!(err.to_string().contains("uleb128"), "{err}");
}
