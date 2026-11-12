//! A key held to a reader: a YubiKey (or any FIDO2 key) through the
//! system's PC/SC, by NFC, or by the smart-card side of a key plugged in.
//! Two of its applications: the YubiKey's OTP slot 2 (HMAC-SHA1), and
//! FIDO2 (CTAP2 in ISO 7816 APDUs), which authenticator-rs drives as it
//! drives a key on USB. Nothing here reaches a network.

use anyhow::{Result, bail, ensure};
use authenticator::crypto::SharedSecret;
use authenticator::ctap2::commands::{RequestCtap1, RequestCtap2};
use authenticator::errors::HIDError;
use authenticator::{
    AuthenticatorInfo, FidoDevice, FidoDeviceIO, FidoProtocol,
};

/// The YubiKey's OTP application.
pub const OTP: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01];
/// FIDO's.
pub const FIDO: &[u8] = &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];

/// A card: an APDU in, its answer (data, then the two status bytes) out.
pub trait Apdu {
    fn raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>>;
}

impl Apdu for pcsc::Card {
    fn raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        let mut b = vec![0; pcsc::MAX_BUFFER_SIZE_EXTENDED];
        Ok(self.transmit(apdu, &mut b)?.to_vec())
    }
}

/// The card that answers `aid`, on a reader now: one held to it, or a
/// key plugged in whose smart-card side does. None with no PC/SC here.
pub fn card(aid: &[u8]) -> Option<pcsc::Card> {
    let ctx = pcsc::Context::establish(pcsc::Scope::User).ok()?;
    let (share, any) = (pcsc::ShareMode::Shared, pcsc::Protocols::ANY);
    let readers = ctx.list_readers_owned().ok()?;
    let mut cards =
        readers.iter().filter_map(|r| ctx.connect(r, share, any).ok());
    cards.find_map(|mut c| select(&mut c, aid).ok().map(|_| c))
}

/// What the card says to `apdu`, all of it (61xx: more to fetch), and its
/// status word.
fn tx(c: &mut impl Apdu, apdu: &[u8]) -> Result<(Vec<u8>, u16)> {
    let (mut r, mut data) = (c.raw(apdu)?, vec![]);
    loop {
        let Some((d, sw)) = r.split_last_chunk::<2>() else {
            bail!("the card said nothing")
        };
        data.extend_from_slice(d);
        match sw {
            [0x61, n] => r = c.raw(&[0x00, 0xC0, 0x00, 0x00, *n])?,
            _ => return Ok((data, u16::from_be_bytes(*sw))),
        }
    }
}

/// `cla ins p1 p2` with `data`, in pieces of 255 bytes chained (ISO
/// 7816-4); the answer to the last.
fn send(
    c: &mut impl Apdu,
    [cla, ins, p1, p2]: [u8; 4],
    data: &[u8],
) -> Result<(Vec<u8>, u16)> {
    let parts: Vec<&[u8]> = match data.is_empty() {
        true => vec![&[]],
        false => data.chunks(255).collect(),
    };
    let last = parts.len() - 1;
    for (i, p) in parts.iter().enumerate() {
        let more = if i < last { 0x10 } else { 0 };
        let mut a = vec![cla | more, ins, p1, p2];
        if !p.is_empty() {
            a.push(p.len() as u8);
            a.extend_from_slice(p);
        }
        if i < last {
            let (_, sw) = tx(c, &a)?;
            ensure!(sw == 0x9000, "the card refused a part: {sw:04X}");
            continue;
        }
        a.push(0x00); // Le: whatever it has
        return tx(c, &a);
    }
    bail!("nothing sent")
}

fn select(c: &mut impl Apdu, aid: &[u8]) -> Result<Vec<u8>> {
    let (d, sw) = send(c, [0x00, 0xA4, 0x04, 0x00], aid)?;
    ensure!(sw == 0x9000, "no such application: {sw:04X}");
    Ok(d)
}

/// The YubiKey's slot 2 HMAC-SHA1 of `challenge`, as ykman asks it: the
/// challenge padded to 64 bytes with a byte unlike its last.
pub fn slot2(c: &mut impl Apdu, challenge: &[u8]) -> Result<Vec<u8>> {
    ensure!(challenge.len() <= 64, "a challenge is 64 bytes at most");
    let pad = (challenge.last() == Some(&0)) as u8;
    let mut ch = challenge.to_vec();
    ch.resize(64, pad);
    let (r, sw) = send(c, [0x00, 0x01, 0x38, 0x00], &ch)?;
    ensure!(
        sw == 0x9000 && r.len() == 20,
        "slot 2 of this YubiKey gave no HMAC-SHA1 answer ({sw:04X})"
    );
    Ok(r)
}

/// A FIDO2 key on a reader, for authenticator-rs: CTAP2's messages as
/// NFCCTAP_MSG APDUs; the protocol (PIN, hmac-secret) is its own.
pub struct Fido<C: Apdu = pcsc::Card> {
    card: C,
    info: Option<AuthenticatorInfo>,
    secret: Option<SharedSecret>,
    ctap1: bool,
}

impl<C: Apdu> Fido<C> {
    pub fn new(card: C) -> Fido<C> {
        Fido { card, info: None, secret: None, ctap1: false }
    }

    /// A CTAP2 command's answer: its status byte, then CBOR.
    fn cbor(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        let c = &mut self.card;
        let (mut d, mut sw) = send(c, [0x80, 0x10, 0x00, 0x00], msg)?;
        // Still at it (a touch, a PIN): asked for the answer again.
        while sw == 0x9100 {
            (d, sw) = send(c, [0x80, 0x11, 0x00, 0x00], &[])?;
        }
        ensure!(sw == 0x9000, "the key refused: {sw:04X}");
        Ok(d)
    }
}

impl<C: Apdu> std::fmt::Debug for Fido<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a key on a reader")
    }
}

impl<C: Apdu> FidoDeviceIO for Fido<C> {
    fn send_msg_cancellable<
        Out,
        Req: RequestCtap1<Output = Out> + RequestCtap2<Output = Out>,
    >(
        &mut self,
        msg: &Req,
        alive: &dyn Fn() -> bool,
    ) -> Result<Out, HIDError> {
        self.send_cbor_cancellable(msg, alive)
    }

    fn send_cbor_cancellable<Req: RequestCtap2>(
        &mut self,
        msg: &Req,
        _: &dyn Fn() -> bool,
    ) -> Result<Req::Output, HIDError> {
        let b = [&[msg.command() as u8][..], &msg.wire_format()?].concat();
        let r = self.cbor(&b).map_err(|_| HIDError::DeviceError)?;
        msg.handle_response_ctap2(self, &r)
    }

    /// U2F alone (CTAP1): not this way.
    fn send_ctap1_cancellable<Req: RequestCtap1>(
        &mut self,
        _: &Req,
        _: &dyn Fn() -> bool,
    ) -> Result<Req::Output, HIDError> {
        Err(HIDError::UnsupportedCommand)
    }
}

impl<C: Apdu> FidoDevice for Fido<C> {
    fn pre_init(&mut self) -> Result<(), HIDError> {
        let s = select(&mut self.card, FIDO);
        s.map(|_| ()).map_err(|_| HIDError::DeviceNotSupported)
    }
    fn initialized(&self) -> bool {
        self.info.is_some()
    }
    fn is_u2f(&mut self) -> bool {
        true
    }
    fn should_try_ctap2(&self) -> bool {
        true
    }
    fn get_authenticator_info(&self) -> Option<&AuthenticatorInfo> {
        self.info.as_ref()
    }
    fn set_authenticator_info(&mut self, info: AuthenticatorInfo) {
        self.info = Some(info)
    }
    fn get_protocol(&self) -> FidoProtocol {
        if self.ctap1 { FidoProtocol::CTAP1 } else { FidoProtocol::CTAP2 }
    }
    fn downgrade_to_ctap1(&mut self) {
        self.ctap1 = true
    }
    fn get_shared_secret(&self) -> Option<&SharedSecret> {
        self.secret.as_ref()
    }
    fn set_shared_secret(&mut self, s: SharedSecret) {
        self.secret = Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A card that answers from a script, and keeps what it was sent.
    #[derive(Default)]
    struct Script {
        sent: Vec<Vec<u8>>,
        replies: std::collections::VecDeque<Vec<u8>>,
    }

    impl Apdu for Script {
        fn raw(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
            self.sent.push(apdu.to_vec());
            Ok(self.replies.pop_front().unwrap_or(vec![0x6F, 0x00]))
        }
    }

    fn script(replies: &[&[u8]]) -> Script {
        let replies = replies.iter().map(|r| r.to_vec()).collect();
        Script { sent: vec![], replies }
    }

    /// Slot 2 is asked as Yubico's own library asks it: INS 01, P1 38,
    /// the challenge padded to 64 with a byte unlike its last; 20 back.
    #[test]
    fn slot_two_is_asked_as_ykman_asks() {
        let answer = [[7u8; 20].as_slice(), &[0x90, 0x00]].concat();
        let mut c = script(&[&answer]);
        let challenge = [[5u8; 31].as_slice(), &[0]].concat();
        assert_eq!(slot2(&mut c, &challenge).unwrap(), [7; 20]);
        let a = &c.sent[0];
        assert_eq!(a[..5], [0x00, 0x01, 0x38, 0x00, 64]);
        assert_eq!(a[5..37], challenge[..]);
        assert!(a[37..69].iter().all(|&b| b == 1), "padded unlike the last");
        assert_eq!(a[69..], [0x00]);
        let mut c = script(&[&[0x6A, 0x80]]);
        assert!(slot2(&mut c, &[1; 32]).is_err());
    }

    /// Long messages go in chained pieces; "still at it" (9100, its data
    /// a keep-alive's, not the answer's) is asked again; a long answer
    /// comes by GET RESPONSE.
    #[test]
    fn apdus_chain_wait_and_fetch() {
        let c = script(&[
            &[0x90, 0x00],
            &[0x01, 0x91, 0x00],
            &[0x00, 0xA1, 0x61, 0x01],
            &[0xB2, 0x90, 0x00],
        ]);
        let mut f = Fido::new(c);
        assert_eq!(f.cbor(&[9; 300]).unwrap(), [0x00, 0xA1, 0xB2]);
        let c = f.card;
        assert_eq!(c.sent[0][..5], [0x90, 0x10, 0x00, 0x00, 255]);
        assert_eq!(c.sent[0].len(), 5 + 255, "no Le on a chained part");
        assert_eq!(c.sent[1][..5], [0x80, 0x10, 0x00, 0x00, 45]);
        assert_eq!(c.sent[1].last(), Some(&0x00));
        assert_eq!(c.sent[2], [0x80, 0x11, 0x00, 0x00, 0x00]);
        assert_eq!(c.sent[3], [0x00, 0xC0, 0x00, 0x00, 0x01]);
    }

    /// authenticator-rs takes a key on a reader as one on USB: it selects
    /// FIDO and reads what the key can do (authenticatorGetInfo).
    #[test]
    fn authenticator_rs_drives_a_key_on_a_reader() {
        // {1: ["FIDO_2_0"], 3: aaguid}
        let mut info = vec![0x00, 0xA2, 0x01, 0x81, 0x68];
        info.extend(b"FIDO_2_0");
        info.extend([0x03, 0x50]);
        info.extend([0x11; 16]);
        info.extend([0x90, 0x00]);
        let c = script(&[b"FIDO_2_0\x90\x00", &info]);
        let mut f = Fido::new(c);
        f.init().unwrap();
        assert_eq!(f.get_protocol(), FidoProtocol::CTAP2);
        let i = f.get_authenticator_info().unwrap();
        assert_eq!(i.aaguid.0, [0x11; 16]);
        assert_eq!(f.card.sent[0][..5], [0x00, 0xA4, 0x04, 0x00, 8]);
        assert_eq!(f.card.sent[1], [0x80, 0x10, 0x00, 0x00, 1, 0x04, 0x00]);
    }
}
