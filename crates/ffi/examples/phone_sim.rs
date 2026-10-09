//! Simulated phone for agent end-to-end tests: drives the same `Warpshot`
//! object the Android app uses, with an INSECURE plaintext keystore.
//!
//! ```text
//! phone_sim <dir> <server_url> pair <qr_text>
//! phone_sim <dir> <server_url> send-text <target_hex> <text>
//! phone_sim <dir> <server_url> send-file <target_hex> <path>
//! phone_sim <dir> <server_url> devices
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::Arc;

use warpshot_ffi::{OutgoingFile, PairConfirm, PlatformKeystore, WarpError, Warpshot};

struct PlainKs;

impl PlatformKeystore for PlainKs {
    fn wrap(&self, _label: String, plain: Vec<u8>) -> Result<Vec<u8>, WarpError> {
        Ok(plain)
    }
    fn unwrap(&self, _label: String, wrapped: Vec<u8>) -> Result<Vec<u8>, WarpError> {
        Ok(wrapped)
    }
}

struct Yes;

impl PairConfirm for Yes {
    fn confirm(&self, sas: String, _peer_name: String, _peer_platform: u64) -> bool {
        println!("{{\"ev\":\"sas\",\"sas\":\"{sas}\"}}");
        true
    }
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 3 {
        eprintln!("usage: phone_sim <dir> <server_url> <cmd> ...");
        std::process::exit(2);
    }
    let w = Warpshot::open(
        a[0].clone(),
        "Sim Phone".into(),
        a[1].clone(),
        Arc::new(PlainKs),
    )
    .expect("open");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let w2 = Arc::clone(&w);
    let res: Result<String, WarpError> = rt.block_on(async move {
        match a[2].as_str() {
            "pair" => w2.pair_scan(a[3].clone(), Arc::new(Yes)).await,
            "send-text" => w2
                .send_text(a[3].clone(), a[4].clone())
                .await
                .map(|()| "sent".into()),
            "send-file" => w2
                .send_files(a[3].clone(), vec![OutgoingFile { path: a[4].clone() }])
                .await
                .map(|()| "sent".into()),
            "devices" => Ok(w2
                .devices()
                .await
                .iter()
                .map(|d| format!("{} {} me={}", d.id, d.name, d.me))
                .collect::<Vec<_>>()
                .join("\n")),
            _ => Ok("unknown command".into()),
        }
    });
    drop(rt);
    match res {
        Ok(s) => println!("{s}"),
        Err(e) => {
            println!("error: {e:?}");
            drop(w);
            std::process::exit(1);
        }
    }
    drop(w);
}
