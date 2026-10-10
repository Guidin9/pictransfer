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
        net::require_direct(&s.conn, std::time::Duration::from_secs(5))
            .await
            .unwrap();
        let conn = s.conn.clone();
        // Direct all the way: the slow-route alert must stay silent.
        let (out, route) = net::watch_route(
            &conn,
            std::time::Duration::from_millis(1),
            s.send_items(items),
            || panic!("slow alert on a direct path"),
        )
        .await;
        assert_eq!(
            route,
            net::Route {
                ever_direct: true,
                slow: false
            }
        );
        out
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

/// Runs one pairing between `display` and `scanner` devices; returns both results.
async fn pair_once(
    disp: &Device,
    scan: &Device,
) -> (
    Result<net::pair::Paired, net::NetError>,
    Result<net::pair::Paired, net::NetError>,
) {
    let ep_d = net::bind(&disp.keys.ik, Relay::Disabled).await.unwrap();
    let ep_s = net::bind(&scan.keys.ik, Relay::Disabled).await.unwrap();
    let mut window = Window::open(
        disp.id(),
        net::dial_info(&ep_d),
        disp.name.clone(),
        disp.group_id(),
        now_ms() / 1000,
    )
    .unwrap();
    let qr = QrPayload::parse(&window.qr_text()).unwrap();
    let r = tokio::join!(
        async {
            let conn = accept_conn(&ep_d).await;
            net::pair::display(
                &ep_d,
                conn,
                &mut window,
                disp,
                now_ms(),
                |_| async { true },
                |_| async { Ok(()) },
            )
            .await
        },
        net::pair::scan(
            &ep_s,
            &qr,
            scan,
            now_ms(),
            |_| async { true },
            |_| async { Ok(()) }
        )
    );
    ep_d.close().await;
    ep_s.close().await;
    r
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pairing_resolution_table_all_rows() {
    // Row 1: none/none → new group (display appends genesis + add).
    let mut pc = Device::new("pc", platform::WINDOWS).unwrap();
    let mut phone = Device::new("phone", platform::ANDROID).unwrap();
    let (d, s) = pair_once(&pc, &phone).await;
    let (d, s) = (d.unwrap(), s.unwrap());
    assert_eq!(d.log.records().len(), 2);
    assert_eq!(d.log.head(), s.log.head());
    pc.log = Some(d.log);
    phone.log = Some(s.log);
    let g = pc.group_id().unwrap();

    // Row 2: display in G, scanner none → display adds the scanner.
    let mut tablet = Device::new("tablet", platform::ANDROID).unwrap();
    let (d, s) = pair_once(&pc, &tablet).await;
    let (d, s) = (d.unwrap(), s.unwrap());
    assert_eq!(d.log.group_id(), g);
    assert_eq!(d.log.records().len(), 3);
    assert!(s.log.is_member(&tablet.id()));
    pc.log = Some(d.log);
    tablet.log = Some(s.log);

    // Row 3: display none, scanner in G → the scanner appends add(display).
    let mut laptop = Device::new("laptop", platform::WINDOWS).unwrap();
    let (d, s) = pair_once(&laptop, &tablet).await;
    let (d, s) = (d.unwrap(), s.unwrap());
    assert_eq!(s.log.group_id(), g);
    assert!(d.log.is_member(&laptop.id()) && d.log.is_member(&tablet.id()));
    assert_eq!(d.log.records().len(), 4);
    laptop.log = Some(d.log);

    // Row 4: both in G (same head) → already paired, no new records.
    let (d, s) = pair_once(&laptop, &tablet).await;
    let (d, s) = (d.unwrap(), s.unwrap());
    assert_eq!(d.log.records().len(), 4);
    assert_eq!(s.log.head(), laptop.head());

    // Row 5: different groups → PAIR_OTHER_GROUP, nothing changes.
    let other_pc = Device::new("other-pc", platform::WINDOWS).unwrap();
    let mut other_phone = Device::new("other-phone", platform::ANDROID).unwrap();
    let (_, s) = pair_once(&other_pc, &other_phone).await;
    other_phone.log = Some(s.unwrap().log);
    let (d, s) = pair_once(&pc, &other_phone).await;
    assert_eq!(
        d.unwrap_err(),
        net::NetError::Closed(warpshot_core::xfer::code::PAIR_OTHER_GROUP)
    );
    assert!(s.is_err());
    let _ = phone;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wake_driven_transfer() {
    use warpshot_core::net::flow::{self, PendingSessions, WakeAction};
    let mut pc = Device::new("pc", platform::WINDOWS).unwrap();
    let mut phone = Device::new("phone", platform::ANDROID).unwrap();
    let (d, s) = pair_once(&pc, &phone).await;
    pc.log = Some(d.unwrap().log);
    phone.log = Some(s.unwrap().log);
    let ep_pc = net::bind(&pc.keys.ik, Relay::Disabled).await.unwrap();
    let ep_phone = net::bind(&phone.keys.ik, Relay::Disabled).await.unwrap();

    // PC (sender) keeps the items pending and seals a connect wake for the phone.
    let mut pending = PendingSessions::default();
    let items = vec![nx::text_item(1, "pano içeriği", now_ms()).unwrap()];
    let session = pending.insert(phone.id(), items.clone()).unwrap();
    let env = flow::connect_wake(&ep_pc, &pc, &phone.id(), session, &items, now_ms()).unwrap();
    assert!(warpshot_core::b64u::encode(&env).len() <= warpshot_core::wake::MAX_ENVELOPE_B64U);

    // Phone opens it (the server/FCM only relayed opaque bytes).
    let mut replay = warpshot_core::wake::ReplayCache::default();
    let (sender, action) = flow::open_wake(&phone, &env, now_ms(), &mut replay).unwrap();
    assert_eq!(sender, pc.id());
    let WakeAction::Connect {
        session: got_session,
        dial,
        preview,
        ..
    } = action
    else {
        panic!("connect expected")
    };
    assert_eq!(got_session, session);
    assert_eq!(preview.unwrap().count, 1);
    // Replaying the same envelope is refused.
    assert!(flow::open_wake(&phone, &env, now_ms(), &mut replay).is_err());

    let pc_log = pc.log.clone().unwrap();
    let phone_log = phone.log.clone().unwrap();
    let dir = tmpdir("wake");
    let policy = Policy {
        dir,
        max_size: 1 << 30,
        accept_large: false,
    };
    let (sent, received) = tokio::join!(
        async {
            let conn = accept_conn(&ep_pc).await;
            let s = nx::accept(&ep_pc, conn, &pc_log).await.unwrap();
            let p = pending
                .take(&s.hello_session, &s.peer)
                .expect("pending session");
            s.send_items(p.items).await
        },
        async {
            let s = flow::answer_connect(&ep_phone, &phone_log, &sender, got_session, &dial)
                .await
                .unwrap();
            s.receive(&policy, |_| true).await
        }
    );
    assert_eq!(sent.unwrap(), vec![(1, true)]);
    assert_eq!(
        received.unwrap()[0].item.text.as_deref(),
        Some("pano içeriği")
    );
    assert!(pending.is_empty());
    ep_pc.close().await;
    ep_phone.close().await;
}
