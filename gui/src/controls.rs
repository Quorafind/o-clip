use image::DynamicImage;
use image::GenericImageView;
use image::imageops::FilterType;

use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateDIBSection, DIB_RGB_COLORS, HBITMAP,
};

pub fn dynamic_image_to_hbitmap(
    img: &DynamicImage,
    max_w: u32,
    max_h: u32,
) -> Option<HBITMAP> {
    if max_w == 0 || max_h == 0 {
        return None;
    }

    let (w, h) = img.dimensions();
    if w == 0 || h == 0 {
        return None;
    }

    let (target_w, target_h) = if w > max_w || h > max_h {
        let scale_w = (max_w as f64) / (w as f64);
        let scale_h = (max_h as f64) / (h as f64);
        let scale = scale_w.min(scale_h).min(1.0);
        (
            ((w as f64) * scale).round().max(1.0) as u32,
            ((h as f64) * scale).round().max(1.0) as u32,
        )
    } else {
        (w, h)
    };

    let img = if target_w != w || target_h != h {
        img.resize_exact(target_w, target_h, FilterType::Triangle)
    } else {
        img.clone()
    };

    let rgba = img.to_rgba8();
    let (w, h) = img.dimensions();
    let byte_len = (w as usize)
        .checked_mul(h as usize)?
        .checked_mul(4)?;

    // Create a top-down 32bpp DIB section so we can copy pixels directly.
    let mut bmi = BITMAPINFO::default();
    bmi.bmiHeader = BITMAPINFOHEADER {
        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: w as i32,
        biHeight: -(h as i32),
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB.0,
        biSizeImage: byte_len as u32,
        ..Default::default()
    };

    let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
    let hbitmap =
        unsafe { CreateDIBSection(None, &bmi, DIB_RGB_COLORS, &mut bits, None, 0).ok()? };
    if bits.is_null() {
        return None;
    }

    // Windows DIB expects BGRA.
    let src = rgba.as_raw();
    let dst = bits as *mut u8;
    unsafe {
        for i in 0..(byte_len / 4) {
            let si = i * 4;
            let di = i * 4;
            *dst.add(di + 0) = src[si + 2]; // B
            *dst.add(di + 1) = src[si + 1]; // G
            *dst.add(di + 2) = src[si + 0]; // R
            *dst.add(di + 3) = src[si + 3]; // A
        }
    }

    Some(hbitmap)
}
