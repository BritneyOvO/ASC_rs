use asc_dex::quick::probe_needed_len;

#[test]
fn a_short_buffer_is_not_enough_to_probe() {
    assert!(probe_needed_len(b"dex\n035\0").is_none());
    assert!(probe_needed_len(&[0; 0x70]).is_none());
}
