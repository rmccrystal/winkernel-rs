pub unsafe fn str_from_slice_unchecked<'a>(slice: &'a [u8]) -> &'a str {
    let mut len = libc::strlen(slice.as_ptr() as _);
    if len > slice.len() {
        len = slice.len();
    }
    core::str::from_utf8_unchecked(&slice[0..len])
}