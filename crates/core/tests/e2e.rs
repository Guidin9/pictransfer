//! In-process end-to-end test: two iroh endpoints over loopback (no relay, no
//! server): pairing (§5) then transfers in both roles (§8).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use warpshot_core::{
    log::platform,
    net::{
        self, Relay,
        store::{Device, now_ms},
        xfer::{self as nx, OutItem, Policy, Source},
    },
    pair::{QrPayload, Window},
    xfer::{Item, kind},
};

fn tmpdir(tag: &str) -> PathBuf {
    let mut b = [0u8; 6];
    warpshot_core::keys::random(&mut b).unwrap();
    let d = std::env::temp_dir().join(format!(
        "warpshot-e2e-{tag}-{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

async fn accept_conn(ep: &iroh::Endpoint) -> iroh::endpoint::Connection {
    let inc = ep.accept().await.expect("incoming");
    inc.accept().expect("accepting").await.expect("connection")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pair_then_transfer_both_ways() {
    let mut pc = Device::new("desk-pc", platform::WINDOWS).unwrap();
    let mut phone = Device::new("phone", platform::ANDROID).unwrap();
    let ep_pc = net::bind(&pc.keys.ik, Relay::Disabled).await.unwrap();
    let ep_phone = net::bind(&phone.keys.ik, Relay::Disabled).await.unwrap();
    assert_eq!(
        net::endpoint_id(&ep_pc),
        pc.id(),
        "iroh id must equal our Ed25519 id"
    );

    // --- Pairing: the PC shows a QR, the phone scans it.
    let mut window = Window::open(
        pc.id(),
        net::dial_info(&ep_pc),
        pc.name.clone(),
        None,
        now_ms() / 1000,
    )
    .unwrap();
    let qr = QrPayload::parse(&window.qr_text()).unwrap();
    let (sas_tx, sas_rx) = tokio::sync::oneshot::channel::<String>();
    let display = async {
        let conn = accept_conn(&ep_pc).await;
        net::pair::display(
            &ep_pc,
            conn,
            &mut window,
            &pc,
            now_ms(),
            |s| async move {
                let _ = sas_tx.send(s.sas);
                true
            },
            |recs| async move {
                assert_eq!(recs.len(), 2, "genesis + add");
                Ok(())
            },
        )
        .await
    };
    let scan = net::pair::scan(
        &ep_phone,
        &qr,
        &phone,
        now_ms(),
        |_| async { true },
        |_| async { Ok(()) },
    );
    let (d, s) = tokio::join!(display, scan);
    let (d, s) = (d.unwrap(), s.unwrap());
    let sas_pc = sas_rx.await.unwrap();
    assert_eq!(sas_pc.len(), 7);
    assert_eq!(d.log.head(), s.log.head());
    assert!(d.log.is_member(&phone.id()) && d.log.is_member(&pc.id()));
    pc.log = Some(d.log);
    phone.log = Some(s.log);

    // A second scan of the same QR is refused (single use).
    let again = tokio::join!(
        async {
            let conn = accept_conn(&ep_pc).await;
            net::pair::display(
                &ep_pc,
                conn,
                &mut window,
                &pc,
                now_ms(),
                |_| async { true },
                |_| async { Ok(()) },
            )
            .await
        },
        net::pair::scan(
            &ep_phone,
            &qr,
            &phone,
            now_ms(),
            |_| async { true },
            |_| async { Ok(()) }
        )
    );
    assert!(again.0.is_err() && again.1.is_err());

    // --- Transfer 1: phone dials the PC and sends (session all-zero → dialer offers).
    let dir_pc = tmpdir("pc");
    let file_src = tmpdir("src").join("../../evil name?.png");
    let file_src = file_src.parent().unwrap().join("evil name?.png");
    let big: Vec<u8> = (0..(64 * 1024 * 3)).map(|i| (i * 7) as u8).collect(); // exact multiple of 64 KiB
    let photo: Vec<u8> = (0..150_000).map(|i| (i % 251) as u8).collect();
    let src_path = std::env::temp_dir().join(format!("warpshot-src-{}.png", now_ms()));
    std::fs::write(&src_path, &photo).unwrap();
    let _ = file_src;
    let mut file = nx::file_item(3, &src_path, now_ms()).unwrap();
    file.item.name = "../../evil name?.png".into();
    let items = vec![
        nx::text_item(1, "merhaba dünya", now_ms()).unwrap(),
        OutItem {
            item: Item {
                id: 2,
                kind: kind::FILE,
                name: "CON.bin".into(),
                mime: "application/octet-stream".into(),
                size: big.len() as u64,
                created_at: now_ms(),
                text: None,
            },
            source: Source::Bytes(big.clone()),
        },
        file,
    ];
    let policy = Policy {
        dir: dir_pc.clone(),
        max_size: 500 << 20,
        accept_large: false,
    };
    let pc_log = pc.log.clone().unwrap();
    let phone_log = phone.log.clone().unwrap();
    let recv = async {
        let conn = accept_conn(&ep_pc).await;
        let s = nx::accept(&ep_pc, conn, &pc_log).await.unwrap();
        s.receive(&policy, |_| true).await
    };
    let send = async {
        let s = nx::dial(
            &ep_phone,
            &phone_log,
            &pc.id(),
            &net::dial_info(&ep_pc),
            [0; 16],
        )
        .await
        .unwrap();
        s.send_items(items).await
    };
    let (r, s) = tokio::join!(recv, send);
    let (r, s) = (r.unwrap(), s.unwrap());
    assert_eq!(s, vec![(1, true), (2, true), (3, true)]);
    assert_eq!(r.len(), 3);
    assert_eq!(r[0].item.text.as_deref(), Some("merhaba dünya"));
    let p2 = r[1].path.clone().unwrap();
    assert_eq!(p2.file_name().unwrap().to_str().unwrap(), "_CON.bin");
    assert_eq!(std::fs::read(&p2).unwrap(), big);
    let p3 = r[2].path.clone().unwrap();
    assert_eq!(p3.parent().unwrap(), dir_pc.as_path(), "no path traversal");
    assert_eq!(p3.file_name().unwrap().to_str().unwrap(), "evil name.png");
    assert_eq!(std::fs::read(&p3).unwrap(), photo);
    #[cfg(windows)]
    {
        let mut ads = p3.as_os_str().to_owned();
        ads.push(":Zone.Identifier");
        assert!(
            std::fs::read_to_string(PathBuf::from(ads))
                .unwrap()
                .contains("ZoneId=3")
        );
    }
    assert!(
        std::fs::read_dir(&dir_pc).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".part"))
    );

    // --- Transfer 2: PC dials the phone, phone declines by policy (too large).
    let dir_phone = tmpdir("phone");
    let small_policy = Policy {
        dir: dir_phone.clone(),
        max_size: 10,
        accept_large: false,
    };
    let big_item = vec![OutItem {
        item: Item {
            id: 9,
            kind: kind::FILE,
            name: "x".into(),
            mime: "a/b".into(),
            size: 11,
            created_at: 0,
            text: None,
        },
        source: Source::Bytes(vec![0; 11]),
    }];
    let (r, s) = tokio::join!(
        async {
            let conn = accept_conn(&ep_phone).await;
            nx::accept(&ep_phone, conn, &phone_log)
                .await
                .unwrap()
                .receive(&small_policy, |_| true)
                .await
        },
        async {
            nx::dial(
                &ep_pc,
                &pc_log,
                &phone.id(),
                &net::dial_info(&ep_phone),
                [0; 16],
            )
            .await
            .unwrap()
            .send_items(big_item)
            .await
        }
    );
    assert_eq!(r.unwrap(), vec![]);
    assert_eq!(
        s.unwrap_err(),
        net::NetError::Declined(warpshot_core::xfer::decline::TOO_LARGE)
    );

    // --- A non-member is refused at admission.
    let stranger = Device::new("stranger", platform::WINDOWS).unwrap();
    let ep_x = net::bind(&stranger.keys.ik, Relay::Disabled).await.unwrap();
    let mut fake_log = pc_log.clone();
    // The stranger pretends PC is in its log by reusing PC's log; PC still refuses it.
    let _ = &mut fake_log;
    let (acc, dial) = tokio::join!(
        async {
            let conn = accept_conn(&ep_pc).await;
            nx::accept(&ep_pc, conn, &pc_log).await.map(|_| ())
        },
        async {
            nx::dial(&ep_x, &fake_log, &pc.id(), &net::dial_info(&ep_pc), [0; 16])
                .await
                .map(|_| ())
        }
    );
    assert_eq!(acc.unwrap_err(), net::NetError::Identity);
    assert!(dial.is_err());

    for ep in [ep_pc, ep_phone, ep_x] {
        ep.close().await;
    }
}
