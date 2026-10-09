//! Device state on disk: wrapped keys, name/platform and the validated log.
//! Files are written atomically (temp file + rename) and re-validated on load.

use std::path::{Path, PathBuf};

use crate::{
    cbor::{self, Encoder, Limits, MapRef, Value},
    keys::{DeviceKeys, EndpointId, Keystore},
    log::{DeviceInfo, GroupId, Head, Log, MAX_RECORDS},
};

use super::NetError;

#[derive(Debug)]
pub struct Device {
    pub keys: DeviceKeys,
    pub name: String,
    pub platform: u64,
    pub log: Option<Log>,
}

impl Device {
    pub fn new(name: &str, platform: u64) -> Result<Self, NetError> {
        let keys = DeviceKeys::generate().map_err(|_| NetError::State("keygen"))?;
        Ok(Self {
            keys,
            name: name.to_owned(),
            platform,
            log: None,
        })
    }

    pub fn id(&self) -> EndpointId {
        self.keys.ik.endpoint_id()
    }

    pub fn info(&self) -> DeviceInfo {
        DeviceInfo {
            name: self.name.clone(),
            platform: self.platform,
            kem_pk: self.keys.kk.public_key(),
            app: Some(env!("CARGO_PKG_VERSION").into()),
        }
    }

    pub fn group_id(&self) -> Option<GroupId> {
        self.log.as_ref().map(Log::group_id)
    }

    pub fn head(&self) -> Option<Head> {
        self.log.as_ref().and_then(Log::head)
    }

    pub fn is_member(&self, id: &EndpointId) -> bool {
        self.log.as_ref().is_some_and(|l| l.is_member(id))
    }

    fn device_path(dir: &Path) -> PathBuf {
        dir.join("device.cbor")
    }

    fn log_path(dir: &Path) -> PathBuf {
        dir.join("log.cbor")
    }

    pub fn save(&self, dir: &Path, ks: &dyn Keystore) -> Result<(), NetError> {
        std::fs::create_dir_all(dir)?;
        let wrapped = self
            .keys
            .to_wrapped(ks)
            .map_err(|_| NetError::State("wrap"))?;
        let mut e = Encoder::new();
        e.map(4)
            .uint(0)
            .uint(1)
            .uint(1)
            .text(&self.name)
            .uint(2)
            .uint(self.platform)
            .uint(3)
            .bytes(&wrapped);
        write_atomic(&Self::device_path(dir), &e.into_bytes())?;
        if let Some(log) = &self.log {
            let mut e = Encoder::new();
            e.map(2)
                .uint(0)
                .bytes(&log.group_id().0)
                .uint(1)
                .array(log.records().len());
            for r in log.records() {
                e.bytes(&r.raw);
            }
            write_atomic(&Self::log_path(dir), &e.into_bytes())?;
        }
        Ok(())
    }

    pub fn load(dir: &Path, ks: &dyn Keystore, now_ms: u64) -> Result<Self, NetError> {
        let raw = std::fs::read(Self::device_path(dir))?;
        let v = cbor::decode(&raw, &Limits::new(64 * 1024))
            .map_err(|_| NetError::State("device file"))?;
        let m = MapRef::new(&v).ok_or(NetError::State("device file"))?;
        let bad = |_| NetError::State("device file");
        if m.uint(0).map_err(bad)? != 1 {
            return Err(NetError::State("device file version"));
        }
        let keys = DeviceKeys::from_wrapped(m.bytes(3).map_err(bad)?, ks)
            .map_err(|_| NetError::State("unwrap"))?;
        let mut d = Self {
            keys,
            name: m.text(1).map_err(bad)?.to_owned(),
            platform: m.uint(2).map_err(bad)?,
            log: None,
        };
        match std::fs::read(Self::log_path(dir)) {
            Ok(raw) => {
                let v = cbor::decode(
                    &raw,
                    &Limits {
                        max_depth: 8,
                        max_input: 8 << 20,
                        max_items: MAX_RECORDS,
                    },
                )
                .map_err(|_| NetError::State("log file"))?;
                let m = MapRef::new(&v).ok_or(NetError::State("log file"))?;
                let g = GroupId(m.fixed(0).map_err(|_| NetError::State("log file"))?);
                let list = m
                    .opt_array(1)
                    .map_err(|_| NetError::State("log file"))?
                    .ok_or(NetError::State("log file"))?;
                let mut recs = Vec::with_capacity(list.len());
                for r in list {
                    let Value::Bytes(b) = r else {
                        return Err(NetError::State("log file"));
                    };
                    recs.push(*b);
                }
                // The stored log is re-validated: disk data is untrusted too.
                let log = Log::from_records(g, recs, now_ms).map_err(|(_, e)| NetError::Log(e))?;
                d.log = Some(log);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok(d)
    }
}

pub fn write_atomic(path: &Path, data: &[u8]) -> Result<(), NetError> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
