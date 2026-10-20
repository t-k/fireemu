//! The RFC 6455 codec: the opening handshake key, frame decoding and encoding, message
//! reassembly, and the protocol errors a server must refuse.

use fireemu_adapter_database::websocket::{
    accept_key, decode, encode, Assembler, CloseCode, Decoded, Frame, Message, Opcode,
    ProtocolError,
};
use proptest::prelude::*;

const LIMIT: usize = 1 << 20;

/// A client frame: masked, as RFC 6455 section 5.3 requires.
fn client_frame(fin: bool, opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let mut out = vec![(u8::from(fin) << 7) | opcode];
    let len = payload.len();
    if len < 126 {
        out.push(0x80 | u8::try_from(len).unwrap());
    } else if len <= 0xFFFF {
        out.push(0x80 | 0x7E);
        out.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    } else {
        out.push(0x80 | 0x7F);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    out
}

#[test]
fn the_accept_key_follows_rfc_6455() {
    // The example of RFC 6455 section 1.3.
    assert_eq!(
        accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    );
}

#[test]
fn masked_frames_decode_and_incomplete_input_waits() {
    let bytes = client_frame(true, 0x1, b"hello", [1, 2, 3, 4]);
    for cut in 0..bytes.len() {
        assert_eq!(
            decode(&bytes[..cut], LIMIT).unwrap(),
            Decoded::Incomplete,
            "{cut}"
        );
    }
    assert_eq!(
        decode(&bytes, LIMIT).unwrap(),
        Decoded::Frame(
            Frame {
                fin: true,
                opcode: Opcode::Text,
                payload: b"hello".to_vec(),
            },
            bytes.len()
        )
    );
}

#[test]
fn extended_lengths_decode() {
    for len in [125, 126, 65_535, 65_536, 70_000] {
        let payload = vec![b'x'; len];
        let bytes = client_frame(true, 0x2, &payload, [9, 8, 7, 6]);
        match decode(&bytes, LIMIT).unwrap() {
            Decoded::Frame(frame, used) => {
                assert_eq!(frame.payload.len(), len);
                assert_eq!(used, bytes.len());
            }
            Decoded::Incomplete => panic!("{len}"),
        }
    }
}

#[test]
fn protocol_violations_are_refused() {
    let unmasked = [0x81, 0x01, b'a'];
    assert_eq!(decode(&unmasked, LIMIT), Err(ProtocolError::Unmasked));
    let mut reserved = client_frame(true, 0x1, b"a", [0; 4]);
    reserved[0] |= 0x40;
    assert_eq!(decode(&reserved, LIMIT), Err(ProtocolError::ReservedBits));
    let unknown = client_frame(true, 0x3, b"a", [0; 4]);
    assert_eq!(
        decode(&unknown, LIMIT),
        Err(ProtocolError::UnknownOpcode(3))
    );
    let long_ping = client_frame(true, 0x9, &[0; 126], [0; 4]);
    assert_eq!(
        decode(&long_ping, LIMIT),
        Err(ProtocolError::BadControlFrame)
    );
    let fragmented_ping = client_frame(false, 0x9, b"a", [0; 4]);
    assert_eq!(
        decode(&fragmented_ping, LIMIT),
        Err(ProtocolError::BadControlFrame)
    );
    let big = client_frame(true, 0x1, &vec![b'a'; 2000], [0; 4]);
    assert_eq!(decode(&big, 1000), Err(ProtocolError::TooBig));
    assert_eq!(ProtocolError::TooBig.close_code(), CloseCode::TooBig);
    assert_eq!(ProtocolError::Unmasked.close_code(), CloseCode::Protocol);
}

#[test]
fn server_frames_are_unmasked_and_final() {
    assert_eq!(encode(Opcode::Text, b"hi"), vec![0x81, 0x02, b'h', b'i']);
    let medium = encode(Opcode::Binary, &[0; 300]);
    assert_eq!(&medium[..4], &[0x82, 126, 0x01, 0x2C]);
    let large = encode(Opcode::Text, &vec![0; 70_000]);
    assert_eq!(&large[..10], &[0x81, 127, 0, 0, 0, 0, 0, 0x01, 0x11, 0x70]);
    assert_eq!(
        encode(Opcode::Close, &[0x03, 0xE8]),
        vec![0x88, 0x02, 0x03, 0xE8]
    );
}

#[test]
fn fragments_reassemble_and_control_frames_interleave() {
    let mut assembler = Assembler::new(LIMIT);
    let frame = |fin, opcode, payload: &[u8]| Frame {
        fin,
        opcode,
        payload: payload.to_vec(),
    };
    assert_eq!(
        assembler.push(frame(false, Opcode::Text, b"he")).unwrap(),
        None
    );
    assert_eq!(
        assembler.push(frame(true, Opcode::Ping, b"p")).unwrap(),
        Some(Message::Ping(b"p".to_vec()))
    );
    assert_eq!(
        assembler
            .push(frame(false, Opcode::Continuation, b"l"))
            .unwrap(),
        None
    );
    assert_eq!(
        assembler
            .push(frame(true, Opcode::Continuation, b"lo"))
            .unwrap(),
        Some(Message::Text("hello".to_owned()))
    );
    assert_eq!(
        assembler
            .push(frame(true, Opcode::Close, &[0x03, 0xE8]))
            .unwrap(),
        Some(Message::Close(Some(1000)))
    );
    assert_eq!(
        assembler.push(frame(true, Opcode::Continuation, b"x")),
        Err(ProtocolError::UnexpectedContinuation)
    );
    assert_eq!(
        assembler.push(frame(false, Opcode::Text, b"a")).unwrap(),
        None
    );
    assert_eq!(
        assembler.push(frame(true, Opcode::Text, b"b")),
        Err(ProtocolError::ExpectedContinuation)
    );
    let mut assembler = Assembler::new(LIMIT);
    assert_eq!(
        assembler.push(frame(true, Opcode::Text, &[0xff])),
        Err(ProtocolError::InvalidUtf8)
    );
    assert_eq!(
        ProtocolError::InvalidUtf8.close_code(),
        CloseCode::InvalidData
    );
    let mut small = Assembler::new(3);
    assert_eq!(small.push(frame(false, Opcode::Text, b"ab")).unwrap(), None);
    assert_eq!(
        small.push(frame(true, Opcode::Continuation, b"cd")),
        Err(ProtocolError::TooBig)
    );
}

proptest! {
    #[test]
    fn any_masked_frame_decodes_to_its_payload(
        payload in prop::collection::vec(any::<u8>(), 0..70_000),
        mask in any::<[u8; 4]>(),
        fin in any::<bool>(),
        trailing in prop::collection::vec(any::<u8>(), 0..8),
    ) {
        let mut bytes = client_frame(fin, 0x2, &payload, mask);
        let length = bytes.len();
        bytes.extend_from_slice(&trailing);
        match decode(&bytes, LIMIT).unwrap() {
            Decoded::Frame(frame, used) => {
                prop_assert_eq!(used, length);
                prop_assert_eq!(frame.fin, fin);
                prop_assert_eq!(frame.payload, payload);
            }
            Decoded::Incomplete => prop_assert!(false, "complete frame read as incomplete"),
        }
    }

    #[test]
    fn encoded_frames_carry_their_length(len in 0usize..70_000) {
        let bytes = encode(Opcode::Text, &vec![b'a'; len]);
        let header = match len {
            0..=125 => 2,
            126..=65_535 => 4,
            _ => 10,
        };
        prop_assert_eq!(bytes.len(), header + len);
        prop_assert_eq!(bytes[0], 0x81);
        prop_assert_eq!(bytes[1] & 0x80, 0, "server frames are not masked");
    }
}

#[test]
fn boundary_lengths_are_accepted() {
    let ping = client_frame(true, 0x9, &[1; 125], [0; 4]);
    assert!(matches!(decode(&ping, LIMIT).unwrap(), Decoded::Frame(..)));
    let exact = client_frame(true, 0x1, b"abcd", [0; 4]);
    assert!(matches!(decode(&exact, 4).unwrap(), Decoded::Frame(..)));
    let empty = client_frame(true, 0x1, b"", [5; 4]);
    assert_eq!(
        decode(&empty, LIMIT).unwrap(),
        Decoded::Frame(
            Frame {
                fin: true,
                opcode: Opcode::Text,
                payload: Vec::new(),
            },
            6
        )
    );
    let frame = |fin, opcode, payload: &[u8]| Frame {
        fin,
        opcode,
        payload: payload.to_vec(),
    };
    let mut assembler = Assembler::new(3);
    assert_eq!(
        assembler.push(frame(true, Opcode::Text, b"abc")).unwrap(),
        Some(Message::Text("abc".to_owned()))
    );
    assert_eq!(
        assembler.push(frame(true, Opcode::Text, b"abcde")),
        Err(ProtocolError::TooBig)
    );
    let mut assembler = Assembler::new(3);
    assert_eq!(
        assembler.push(frame(false, Opcode::Text, b"ab")).unwrap(),
        None
    );
    assert_eq!(
        assembler
            .push(frame(true, Opcode::Continuation, b"c"))
            .unwrap(),
        Some(Message::Text("abc".to_owned()))
    );
}

#[test]
fn close_payloads_follow_rfc_6455() {
    let close = |payload: &[u8]| {
        Assembler::new(LIMIT).push(Frame {
            fin: true,
            opcode: Opcode::Close,
            payload: payload.to_vec(),
        })
    };
    assert_eq!(close(&[]), Ok(Some(Message::Close(None))));
    assert_eq!(close(&[0x03]), Err(ProtocolError::BadClose));
    for code in [1000u16, 1001, 1002, 1003, 1007, 1011, 1014, 3000, 4999] {
        assert_eq!(
            close(&code.to_be_bytes()),
            Ok(Some(Message::Close(Some(code)))),
            "{code}"
        );
    }
    for code in [0u16, 999, 1004, 1005, 1006, 1015, 1016, 2999, 5000] {
        assert_eq!(
            close(&code.to_be_bytes()),
            Err(ProtocolError::BadClose),
            "{code}"
        );
    }
    assert_eq!(
        close(&[0x03, 0xE8, b'o', b'k']),
        Ok(Some(Message::Close(Some(1000))))
    );
    assert_eq!(close(&[0x03, 0xE8, 0xff]), Err(ProtocolError::InvalidUtf8));
    assert_eq!(ProtocolError::BadClose.close_code(), CloseCode::Protocol);
    assert_eq!(CloseCode::Normal.code(), 1000);
    assert_eq!(CloseCode::Protocol.code(), 1002);
    assert_eq!(CloseCode::InvalidData.code(), 1007);
    assert_eq!(CloseCode::TooBig.code(), 1009);
}
