//! QR codes from a camera (nokhwa) or a picture, read by rqrr, then rxing.
//! `PASA_CAMERA`: another camera's number, or a picture to read instead.

use anyhow::{Context, Result, bail, ensure};
use nokhwa::pixel_format::LumaFormat;
use nokhwa::utils::{
    CameraFormat, CameraIndex, FrameFormat, RequestedFormat,
    RequestedFormatType, Resolution,
};
use std::path::Path;

/// 8-bit luma, row-major.
#[derive(Clone)]
pub struct Frame {
    pub w: usize,
    pub h: usize,
    pub px: Vec<u8>,
}

pub enum Camera {
    On(Box<nokhwa::Camera>),
    Still(Frame),
}

impl Camera {
    pub fn open() -> Result<Camera> {
        let at = std::env::var("PASA_CAMERA").ok();
        if let Some(f) = at.as_deref().filter(|f| Path::new(f).is_file()) {
            return Ok(Camera::Still(picture(Path::new(f))?));
        }
        let i = at.as_deref().map_or(Ok(0), str::parse);
        let i = i.context("PASA_CAMERA: a camera's number, or a picture")?;
        allowed()?;
        // Packed YUYV: its luma is every other byte, on macOS as on Linux.
        let want = CameraFormat::new(Resolution::new(1280, 720), YUYV, 30);
        let f = RequestedFormat::new::<LumaFormat>(
            RequestedFormatType::Closest(want),
        );
        let mut c = nokhwa::Camera::new(CameraIndex::Index(i), f)
            .map_err(|e| anyhow::anyhow!("no camera here: {e}"))?;
        c.open_stream()?;
        Ok(Camera::On(Box::new(c)))
    }

    pub fn frame(&mut self) -> Result<Frame> {
        match self {
            Camera::Still(f) => {
                std::thread::sleep(std::time::Duration::from_millis(125));
                Ok(f.clone())
            }
            Camera::On(c) => {
                let b = c.frame()?;
                let r = b.resolution();
                let (w, h) = (r.width() as usize, r.height() as usize);
                grey(w, h, b.source_frame_format(), b.buffer())
            }
        }
    }
}

const YUYV: FrameFormat = FrameFormat::YUYV;

/// macOS asks the person, once, whether pasa may use the camera.
#[cfg(target_os = "macos")]
fn allowed() -> Result<()> {
    if nokhwa::nokhwa_check() {
        return Ok(());
    }
    let (tx, rx) = std::sync::mpsc::channel();
    nokhwa::nokhwa_initialize(move |ok| {
        let _ = tx.send(ok);
    });
    let wait = std::time::Duration::from_secs(120);
    ensure!(
        rx.recv_timeout(wait).unwrap_or(false),
        "pasa may not use the camera: System Settings, Privacy & Security, \
         Camera"
    );
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn allowed() -> Result<()> {
    Ok(())
}

pub fn picture(p: &Path) -> Result<Frame> {
    let i = image::ImageReader::open(p)?.with_guessed_format()?.decode()?;
    let i = i.to_luma8();
    let (w, h) = (i.width() as usize, i.height() as usize);
    Ok(Frame { w, h, px: i.into_raw() })
}

/// Rows may be padded (macOS pads them): a row's stride is the length / h.
fn grey(w: usize, h: usize, f: FrameFormat, b: &[u8]) -> Result<Frame> {
    ensure!(w > 0 && h > 0, "an empty frame");
    let luma = |stride: usize, step: usize, off: usize| {
        let mut px = Vec::with_capacity(w * h);
        for y in 0..h {
            let at = y * stride + off;
            px.extend(b.get(at..at + w * step - off)?.iter().step_by(step));
        }
        Some(px)
    };
    let px = match f {
        FrameFormat::YUYV => luma(b.len() / h, 2, 0),
        FrameFormat::GRAY => luma(b.len() / h, 1, 0),
        // The luma plane first, then half as much colour.
        FrameFormat::NV12 => luma(b.len() * 2 / (3 * h), 1, 0),
        // Green, near enough to luma for a black and white code.
        FrameFormat::RAWRGB | FrameFormat::RAWBGR => luma(b.len() / h, 3, 1),
        FrameFormat::MJPEG => {
            let j = image::ImageFormat::Jpeg;
            let i = image::load_from_memory_with_format(b, j)?.to_luma8();
            let (w, h) = (i.width() as usize, i.height() as usize);
            return Ok(Frame { w, h, px: i.into_raw() });
        }
    };
    let Some(px) = px.filter(|p| p.len() == w * h) else {
        bail!("the camera's {f} frame is short")
    };
    Ok(Frame { w, h, px })
}

pub fn read(f: &Frame) -> Option<String> {
    let (w, h) = (f.w, f.h);
    let px = |x, y| f.px.get(y * w + x).copied().unwrap_or(255);
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(w, h, px);
    let codes = img.detect_grids();
    let rq = codes.into_iter().find_map(|g| g.decode().ok()).map(|(_, t)| t);
    rq.or_else(|| {
        use rxing::{BarcodeFormat, DecodeHintValue, DecodeHints};
        let mut hints =
            DecodeHints::default().with(DecodeHintValue::TryHarder(true));
        let (fw, fh) = (u32::try_from(w).ok()?, u32::try_from(h).ok()?);
        let q = Some(BarcodeFormat::QR_CODE);
        let r = rxing::helpers::detect_in_luma_slice_with_hints(
            &f.px, fw, fh, q, &mut hints,
        );
        r.ok().map(|r| r.getText().to_string())
    })
}

pub fn scan() -> Result<String> {
    let mut c = Camera::open()?;
    loop {
        if let Some(t) = read(&c.frame()?) {
            return Ok(t);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: usize = 1280;
    const H: usize = 720;

    fn tilted(text: &str) -> Frame {
        let code = qrcode::QrCode::new(text).unwrap();
        let (n, dark) = (code.width(), code.to_colors());
        let (px, q, x0, y0) = (6.0, 4.0, 300.0, 40.0);
        let tilt: f64 = 0.12;
        let (s, c) = tilt.sin_cos();
        let mut f = vec![140u8; W * H];
        for (i, p) in f.iter_mut().enumerate() {
            let (x, y) = ((i % W) as f64 - x0, (i / W) as f64 - y0);
            // Back to the code: undo the tilt, then a module each `px`.
            let (u, v) = ((c * x + s * y) / px - q, (c * y - s * x) / px - q);
            let side = n as f64 + 2.0 * q;
            if (-q..side - q).contains(&u) && (-q..side - q).contains(&v) {
                let (m, k) = (u.floor(), v.floor());
                let on = m >= 0.0
                    && k >= 0.0
                    && (m as usize) < n
                    && (k as usize) < n;
                let on = on
                    && dark[k as usize * n + m as usize] == qrcode::Color::Dark;
                *p = if on { 20 } else { 235 };
            }
        }
        Frame { w: W, h: H, px: f }
    }

    #[test]
    fn a_tilted_code_in_a_frame_reads() {
        let text = format!("PAIRIR1:{}", "A2VO6QK5PMTRK623".repeat(37));
        assert_eq!(read(&tilted(&text)), Some(text));
        assert_eq!(read(&Frame { w: W, h: H, px: vec![140; W * H] }), None);
    }

    #[test]
    fn camera_formats_become_grey() {
        let text = format!("PAIRIR1:{}", "A2VO6QK5PMTRK623".repeat(20));
        let g = tilted(&text);
        let pad = 64;
        let yuyv: Vec<u8> =
            g.px.chunks(W)
                .flat_map(|r| {
                    let r = r.iter().flat_map(|&y| [y, 128]);
                    r.chain(std::iter::repeat_n(7, pad))
                })
                .collect();
        let nv12 = [&g.px[..], &vec![128; W * H / 2]].concat();
        let rgb: Vec<u8> = g.px.iter().flat_map(|&y| [9, y, 9]).collect();
        for (f, b) in [(YUYV, yuyv), (FrameFormat::NV12, nv12)] {
            assert_eq!(grey(W, H, f, &b).unwrap().px, g.px, "{f}");
        }
        assert_eq!(grey(W, H, FrameFormat::RAWRGB, &rgb).unwrap().px, g.px);
        assert!(grey(W, H, YUYV, &[0; 100]).is_err());
        let img = image::GrayImage::from_raw(W as u32, H as u32, g.px.clone());
        let img = image::DynamicImage::ImageLuma8(img.unwrap());
        let mut jpeg = std::io::Cursor::new(vec![]);
        img.write_to(&mut jpeg, image::ImageFormat::Jpeg).unwrap();
        let j = grey(W, H, FrameFormat::MJPEG, jpeg.get_ref()).unwrap();
        assert_eq!(read(&j), Some(text.clone()));
        let at = std::env::temp_dir()
            .join(format!("pasa-scan-{}.png", std::process::id()));
        img.save(&at).unwrap();
        let p = picture(&at);
        std::fs::remove_file(&at).unwrap();
        assert_eq!(read(&p.unwrap()), Some(text));
    }
}
