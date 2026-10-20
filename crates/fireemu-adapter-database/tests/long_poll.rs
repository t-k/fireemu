//! The long-polling transport's text layer (`/.lp`): requests, segment reassembly and the
//! scripts the server answers with. Unless a test says otherwise, every expected text is what
//! the official emulator (firebase-database-emulator v4.11.2) answered.

use std::collections::BTreeMap;

use fireemu_adapter_database::long_poll::{
    decode_base64, disconnect_frame, packet, parse, reset, start_script, LpRequest, Reassembler,
    Segment, NOTHING,
};
use proptest::prelude::*;

fn params(query: &str) -> BTreeMap<String, String> {
    fireemu_adapter_database::request::split_target(&format!("/.lp?{query}")).1
}

#[test]
fn requests_are_told_apart_by_their_parameters() {
    assert_eq!(
        parse(&params("start=t&ser=1&cb=3&v=5&ns=x")),
        LpRequest::Start { callback: Some(3) }
    );
    assert_eq!(
        parse(&params("dframe=t&id=5&pw=abc&ns=x")),
        LpRequest::DisconnectFrame {
            id: 5,
            password: "abc".to_owned()
        }
    );
    assert_eq!(
        parse(&params("disconn=t&id=5&pw=abc")),
        LpRequest::Disconnect {
            id: "5".to_owned(),
            password: "abc".to_owned()
        }
    );
    assert_eq!(
        parse(&params(
            "id=6&pw=pw&ser=9&ns=x&seg0=0&ts0=1&d0=eyJ0IjoiZCJ9&seg1=1&ts1=2&d1=YQ.."
        )),
        LpRequest::Poll {
            id: "6".to_owned(),
            password: "pw".to_owned(),
            segments: vec![
                Segment {
                    number: 0,
                    total: 1,
                    data: "eyJ0IjoiZCJ9".to_owned()
                },
                Segment {
                    number: 1,
                    total: 2,
                    data: "YQ..".to_owned()
                },
            ],
        }
    );
    // A request naming no connection is a poll of an unknown one.
    assert_eq!(
        parse(&params("")),
        LpRequest::Poll {
            id: String::new(),
            password: String::new(),
            segments: Vec::new()
        }
    );
}

#[test]
fn the_callback_number_is_read_as_the_official_emulator_reads_it() {
    let callback = |cb: &str| match parse(&params(&format!("start=t&cb={cb}&v=5"))) {
        LpRequest::Start { callback } => callback,
        other => panic!("{other:?}"),
    };
    assert_eq!(callback("12"), Some(12));
    assert_eq!(callback("007"), Some(7));
    assert_eq!(callback(""), Some(0));
    assert_eq!(callback("2147483647"), Some(2_147_483_647));
    for refused in ["2147483648", "-5", "+3", "abc", "a_b", "1.2", "%22%5D"] {
        assert_eq!(callback(refused), None, "{refused}");
    }
    assert_eq!(
        parse(&params("start=t&v=5")),
        LpRequest::Start { callback: None }
    );
}

#[test]
fn disconnect_frames_need_a_numeric_id_and_an_alphanumeric_password() {
    let frame = |query: &str| parse(&params(&format!("dframe=t&{query}")));
    assert_eq!(
        frame("id=05&pw=abc"),
        LpRequest::DisconnectFrame {
            id: 5,
            password: "abc".to_owned()
        }
    );
    assert_eq!(
        frame("id=-5&pw="),
        LpRequest::DisconnectFrame {
            id: -5,
            password: String::new()
        }
    );
    for refused in [
        "id=abc&pw=abc",
        "id=99999999999&pw=abc",
        "id=5&pw=ab_c",
        "id=5&pw=a%3Cb",
        "id=5",
    ] {
        assert_eq!(frame(refused), LpRequest::Refused, "{refused}");
    }
}

#[test]
fn scripts_follow_the_official_emulator() {
    assert_eq!(
        start_script(Some(3), "8", "NFWUXkYU4y", r#"{"t":"c"}"#),
        "\nfunction pLPCommand(c, a1, a2, a3, a4) {\nparent.window[\"pLPCommand3\"] && parent.window[\"pLPCommand3\"](c, a1, a2, a3, a4);\n}\nfunction pRTLPCB(pN, data) {\nparent.window[\"pRTLPCB3\"] && parent.window[\"pRTLPCB3\"](pN, data);\n}\n         pLPCommand('start','8','NFWUXkYU4y');\npRTLPCB(0,[{\"t\":\"c\"}]);\n"
    );
    assert_eq!(
        start_script(None, "12", "9IZcO8AaIw", r#"{"t":"c"}"#),
        "pLPCommand('start','12','9IZcO8AaIw');\npRTLPCB(0,[{\"t\":\"c\"}]);\n"
    );
    assert_eq!(packet(1, &[]), "pRTLPCB(1,[]);\n");
    assert_eq!(
        packet(6, &[r#"{"a":1}"#.to_owned(), r#"{"b":2}"#.to_owned()]),
        "pRTLPCB(6,[{\"a\":1},{\"b\":2}]);\n"
    );
    assert_eq!(
        reset("127.0.0.1:19400"),
        "pRTLPCB(0,[{\"t\":\"c\",\"d\":{\"t\":\"r\",\"d\":\"127.0.0.1:19400\"}}]);\npLPCommand('close');\n"
    );
    assert_eq!(NOTHING, "<!-- -->");
    assert_eq!(
        disconnect_frame(10, "wyEMNfnUJF"),
        "<html><body><script>\nfunction EnvSendPing(destURL) {\ntry{\nvar xhr=new XMLHttpRequest();\nxhr.open(\"GET\", destURL, false);\nxhr.send(null);\n} catch (e) { }\n}\nfunction EnvDisconnect() {\nEnvSendPing(\"/.lp?disconn=t&id=10&pw=wyEMNfnUJF\");\n}\nif(window.addEventListener)\nwindow.addEventListener('unload',EnvDisconnect,false);\nelse if(window.attachEvent)\nwindow.attachEvent('onunload',EnvDisconnect);\n</script></body></html>"
    );
}

#[test]
fn base64_reads_the_sdks_web_safe_form() {
    assert_eq!(decode_base64("eyJ0IjoiZCJ9").unwrap(), br#"{"t":"d"}"#);
    assert_eq!(decode_base64("YQ..").unwrap(), b"a");
    assert_eq!(decode_base64("YWI.").unwrap(), b"ab");
    assert_eq!(decode_base64("YQ==").unwrap(), b"a");
    assert_eq!(decode_base64("-_8").unwrap(), [0xFB, 0xFF]);
    assert_eq!(decode_base64("").unwrap(), b"");
    for bad in ["%%%", "Y", "YQ.Q", "Y\u{e9}", "YQ....", "YQ.", "YQ......"] {
        assert!(decode_base64(bad).is_none(), "{bad}");
    }
}

fn seg(number: u64, total: u64, data: &str) -> Segment {
    Segment {
        number,
        total,
        data: data.to_owned(),
    }
}

#[test]
fn packets_are_joined_in_segment_order() {
    let mut r = Reassembler::new(1 << 20);
    // eyJhIjoxfQ.. is {"a":1}; split over two segments, the second arriving first.
    assert_eq!(
        r.add(vec![seg(1, 2, "IjoxfQ..")]).unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(
        r.add(vec![seg(0, 2, "eyJh")]).unwrap(),
        vec![r#"{"a":1}"#.to_owned()]
    );
    // A later packet waits for the one before it.
    assert_eq!(
        r.add(vec![seg(3, 1, "eyJjIjozfQ..")]).unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(
        r.add(vec![seg(2, 1, "eyJiIjoyfQ..")]).unwrap(),
        vec![r#"{"b":2}"#.to_owned(), r#"{"c":3}"#.to_owned()]
    );
    // A segment already used is ignored.
    assert_eq!(
        r.add(vec![seg(0, 1, "eyJ4IjoxfQ..")]).unwrap(),
        Vec::<String>::new()
    );
    // Bad base64 or text that is not UTF-8 fails the request.
    assert!(r.add(vec![seg(4, 1, "%%%")]).is_err());
}

#[test]
fn waiting_segments_are_bounded() {
    let mut r = Reassembler::new(16);
    let used: Vec<Segment> = (0..4).map(|n| seg(n, 1, "YQ..")).collect();
    assert_eq!(r.add(used.clone()).unwrap().len(), 4);
    // Segments already used do not wait again.
    assert!(r.add(used).unwrap().is_empty());
    assert!(r.add(vec![seg(5, 2, "aaaaaaaa")]).is_ok());
    // Up to the limit may wait; one byte more may not.
    assert!(r.add(vec![seg(7, 1, "aaaaaaaa")]).is_ok());
    assert!(r.add(vec![seg(8, 1, "a")]).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn any_split_and_arrival_order_gives_back_the_messages(
        messages in prop::collection::vec("[ -~é😀]{0,40}", 1..5),
        cuts in prop::collection::vec(1usize..12, 1..5),
        order in any::<prop::sample::Index>(),
    ) {
        // Encode each message as the SDK does and cut it into segments.
        let mut segments = Vec::new();
        let mut number = 0u64;
        for message in &messages {
            let text = fireemu_core_database::hash::base64(message.as_bytes())
                .replace('+', "-").replace('/', "_").replace('=', ".");
            let size = cuts[segments.len() % cuts.len()];
            let pieces: Vec<String> = if text.is_empty() {
                vec![String::new()]
            } else {
                text.as_bytes().chunks(size).map(|c| String::from_utf8(c.to_vec()).unwrap()).collect()
            };
            let total = pieces.len() as u64;
            for piece in pieces {
                segments.push(seg(number, total, &piece));
                number += 1;
            }
        }
        // Deliver them rotated: every order still reassembles in sequence.
        let shift = order.index(segments.len());
        segments.rotate_left(shift);
        let mut r = Reassembler::new(1 << 20);
        let mut got = Vec::new();
        for s in segments {
            got.extend(r.add(vec![s]).unwrap());
        }
        prop_assert_eq!(got, messages);
    }
}
