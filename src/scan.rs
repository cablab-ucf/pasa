//! A QR code from the camera, offline: ffmpeg reads the camera (V4L2 on
//! Linux, AVFoundation on macOS) and hands on grey frames through a pipe;
//! rqrr, then rxing (ZXing's way), read the code in them. Frames stay in memory: nothing is written,
//! nothing sent. `PASA_CAMERA` names another camera, or a picture or film
//! of the code.

use anyhow::{Context, Result, bail};
use std::io::Read;
use std::process::{Child, Command, Stdio};

/// A frame's size: room for a pairing's code, some 80 modules a side.
pub const W: usize = 1280;
pub const H: usize = 720;

/// The camera, while it is on: ffmpeg, ended when this is dropped.
pub struct Camera(Child);

impl Camera {
    pub fn open() -> Result<Camera> {
        let at = std::env::var("PASA_CAMERA").ok();
        let mut c = Command::new("ffmpeg");
        c.args(["-loglevel", "error", "-nostdin"]);
        match at.as_deref() {
            // A picture, again and again; a film, from the start again.
            Some(f) if std::path::Path::new(f).is_file() => {
                let ext = f.rsplit('.').next().unwrap_or("").to_lowercase();
                match ["png", "jpg", "jpeg", "bmp", "webp"].contains(&&*ext) {
                    true => c.args(["-loop", "1", "-framerate", "8", "-i", f]),
                    false => c.args(["-stream_loop", "-1", "-re", "-i", f]),
                }
            }
            #[cfg(target_os = "macos")]
            d => c
                .args(["-f", "avfoundation", "-framerate", "30"])
                .args(["-i", d.unwrap_or("0")]),
            #[cfg(not(target_os = "macos"))]
            d => c.args(["-f", "v4l2", "-i", d.unwrap_or("/dev/video0")]),
        };
        let fit = format!(
            "fps=8,scale={W}:{H}:force_original_aspect_ratio=decrease,\
             pad={W}:{H}:(ow-iw)/2:(oh-ih)/2,format=gray"
        );
        c.args(["-vf", &fit, "-f", "rawvideo", "-"]);
        c.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let c = c.spawn().context("ffmpeg is needed to scan a QR code")?;
        Ok(Camera(c))
    }

    /// The next frame, W×H grey bytes; or why there is none.
    pub fn frame(&mut self) -> Result<Vec<u8>> {
        let mut f = vec![0; W * H];
        let out = self.0.stdout.as_mut().context("ffmpeg")?;
        if out.read_exact(&mut f).is_err() {
            let mut why = String::new();
            if let Some(e) = self.0.stderr.as_mut() {
                let _ = e.read_to_string(&mut why);
            }
            bail!("the camera gave nothing: {}", why.trim());
        }
        Ok(f)
    }
}

impl Drop for Camera {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The text of a QR code in a W×H frame, if one is there.
pub fn read(f: &[u8]) -> Option<String> {
    let px = |x, y| f.get(y * W + x).copied().unwrap_or(255);
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(W, H, px);
    let codes = img.detect_grids();
    let rq = codes.into_iter().find_map(|g| g.decode().ok()).map(|(_, t)| t);
    rq.or_else(|| {
        use rxing::{BarcodeFormat, DecodeHintValue, DecodeHints};
        let mut h =
            DecodeHints::default().with(DecodeHintValue::TryHarder(true));
        let (w, q) = ((W as u32, H as u32), Some(BarcodeFormat::QR_CODE));
        let r = rxing::helpers::detect_in_luma_slice_with_hints(
            f, w.0, w.1, q, &mut h,
        );
        r.ok().map(|r| r.getText().to_string())
    })
}

/// Frames until one holds a code: its text.
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

    /// A pairing's QR code, as a camera sees it held at an angle, small
    /// in a corner of the frame, on a grey ground: read whole.
    #[test]
    fn a_tilted_code_in_a_frame_reads() {
        let text = format!("PAIRIR1:{}", "A2VO6QK5PMTRK623".repeat(37));
        let code = qrcode::QrCode::new(&text).unwrap();
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
        assert_eq!(read(&f), Some(text));
        assert_eq!(read(&vec![140; W * H]), None);
    }
}
