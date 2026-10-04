//! One class, handed to `ddc-dec` after ASC has already found it.
//!
//! `ddc-dec` resolves instructions through the DEX id tables, so the image
//! that contains the class is parsed. Only that class and its nested
//! members are registered. The other classes in the image are not decompiled.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use ddc_dec::classdec::{decompile_class, ClassOptions, PendingMonitor};
use ddc_dec::{install_case_renames, DexPool};
use ddc_dex::DexFile;

use crate::{Error, Result};

/// Decompile one Dalvik descriptor (`Lcom/example/Foo;`).
pub fn decompile_one(bytes: Vec<u8>, descriptor: &str) -> Result<String> {
    let internal = descriptor_to_internal(descriptor);
    let image = Image::open_family(bytes, &internal)?;
    image.class_source(descriptor)
}

/// Every top-level class in one inflated image. Used by `dump`, which has
/// already asked for each class in the entry.
pub struct Image {
    pool: Arc<DexPool>,
}

impl Image {
    pub fn open(bytes: Vec<u8>) -> Result<Self> {
        Self::from_dex(DexFile::parse(bytes).map_err(Error::new)?)
    }

    fn open_family(bytes: Vec<u8>, internal: &str) -> Result<Self> {
        let mut dex = DexFile::parse(bytes).map_err(Error::new)?;
        let names: Vec<String> = dex
            .class_defs
            .iter()
            .map(|def| dex.class_name(def.class_idx))
            .collect();
        let mut index = 0;
        dex.class_defs.retain(|_| {
            let keep = in_family(&names[index], internal);
            index += 1;
            keep
        });
        if dex.class_defs.is_empty() {
            bail!("Class L{internal}; not found in APK.");
        }
        Self::from_dex(dex)
    }

    fn from_dex(dex: DexFile) -> Result<Self> {
        let mut pool = DexPool::new();
        pool.add_dex_lazy(dex);
        install_case_renames(&pool);
        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    fn class_source(&self, descriptor: &str) -> Result<String> {
        let internal = descriptor_to_internal(descriptor);
        self.render(&internal)
    }

    pub fn top_level(&self) -> Vec<String> {
        ddc_dec::top_level_classes(&self.pool)
    }

    pub fn render(&self, internal: &str) -> Result<String> {
        let class = self.pool.get(internal).ok_or_else(|| {
            Error::new(format!("Class {internal} not found in APK."))
        })?;
        let pending: Mutex<Vec<PendingMonitor>> = Mutex::new(Vec::new());
        let opts = ClassOptions { provenance: false };
        match decompile_class(&self.pool, class, &opts, &pending) {
            Ok(text) => Ok(text),
            Err(err) => {
                let message = format!("{err:#}");
                if message.contains("deferred to monitored thread") {
                    wait_pending(pending)
                } else {
                    Err(Error::new(message))
                }
            }
        }
    }
}

/// `Foo` itself, plus `Foo$Bar` and `Foo$1`. `FooBar` is a different class.
fn in_family(name: &str, internal: &str) -> bool {
    name == internal
        || name
            .strip_prefix(internal)
            .is_some_and(|rest| rest.starts_with('$'))
}

fn wait_pending(pending: Mutex<Vec<PendingMonitor>>) -> Result<String> {
    let mut queued = pending.into_inner().expect("pending monitor lock poisoned");
    let Some((rx, name, deadline)) = queued.pop() else {
        bail!("decompile was deferred without a worker");
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    match rx.recv_timeout(remaining) {
        Ok(Ok(text)) => Ok(text),
        Ok(Err(err)) => Err(Error::new(err)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            Err(Error::new(format!("{name}: decompile timed out")))
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(Error::new(format!("{name}: decompile worker stopped")))
        }
    }
}

fn descriptor_to_internal(descriptor: &str) -> String {
    descriptor
        .strip_prefix('L')
        .and_then(|rest| rest.strip_suffix(';'))
        .unwrap_or(descriptor)
        .to_string()
}

pub fn internal_to_descriptor(internal: &str) -> String {
    if internal.starts_with('[') || (internal.starts_with('L') && internal.ends_with(';')) {
        internal.to_string()
    } else {
        format!("L{internal};")
    }
}
