use std::{borrow::Cow, io::Cursor, thread, time::Duration};

use anyhow::Context;
use arboard::{Clipboard, ImageData};
use clipmesh_protocol::crypto::{ClipboardItem, content_hash};
use image::{DynamicImage, ImageFormat, RgbaImage};
use tokio::sync::mpsc;

pub enum ClipboardCommand {
    Write(ClipboardItem),
    Stop,
}

pub struct ClipboardHandle {
    pub commands: std::sync::mpsc::Sender<ClipboardCommand>,
    pub changes: mpsc::Receiver<ClipboardItem>,
}

pub fn start() -> ClipboardHandle {
    let (commands_tx, commands_rx) = std::sync::mpsc::channel();
    let (changes_tx, changes_rx) = mpsc::channel(16);
    thread::Builder::new()
        .name("clipmesh-clipboard".into())
        .spawn(move || run(commands_rx, changes_tx))
        .expect("clipboard thread");
    ClipboardHandle {
        commands: commands_tx,
        changes: changes_rx,
    }
}

pub fn write_once(item: &ClipboardItem) -> anyhow::Result<()> {
    let mut clipboard = Clipboard::new().context("clipboard is unavailable")?;
    write_item(&mut clipboard, item)?;
    // X11 clipboard ownership is process-bound. Give a clipboard manager time to claim it.
    thread::sleep(Duration::from_secs(2));
    Ok(())
}

fn run(
    commands: std::sync::mpsc::Receiver<ClipboardCommand>,
    changes: mpsc::Sender<ClipboardItem>,
) {
    let mut clipboard = loop {
        match Clipboard::new() {
            Ok(value) => break value,
            Err(error) => {
                tracing::warn!(%error, "clipboard unavailable; retrying");
                thread::sleep(Duration::from_secs(2));
            }
        }
    };
    let mut last_hash: Option<String> = None;
    loop {
        while let Ok(command) = commands.try_recv() {
            match command {
                ClipboardCommand::Write(item) => match write_item(&mut clipboard, &item) {
                    Ok(()) => last_hash = Some(content_hash(&item)),
                    Err(error) => tracing::warn!(%error, "could not write clipboard"),
                },
                ClipboardCommand::Stop => return,
            }
        }
        if let Some(item) = read_item(&mut clipboard) {
            let hash = content_hash(&item);
            if last_hash.as_ref() != Some(&hash) {
                last_hash = Some(hash);
                if changes.blocking_send(item).is_err() {
                    return;
                }
            }
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn read_item(clipboard: &mut Clipboard) -> Option<ClipboardItem> {
    if let Ok(image) = clipboard.get_image() {
        let rgba = RgbaImage::from_raw(
            image.width as u32,
            image.height as u32,
            image.bytes.into_owned(),
        )?;
        let mut cursor = Cursor::new(Vec::new());
        if DynamicImage::ImageRgba8(rgba)
            .write_to(&mut cursor, ImageFormat::Png)
            .is_ok()
        {
            return Some(ClipboardItem::Png {
                bytes: cursor.into_inner(),
                width: image.width as u32,
                height: image.height as u32,
            });
        }
    }
    clipboard
        .get_text()
        .ok()
        .map(|value| ClipboardItem::Text(value.into_bytes()))
}

fn write_item(clipboard: &mut Clipboard, item: &ClipboardItem) -> anyhow::Result<()> {
    match item {
        ClipboardItem::Text(bytes) => clipboard
            .set_text(std::str::from_utf8(bytes)?.to_owned())
            .context("clipboard rejected text"),
        ClipboardItem::Png { bytes, .. } => {
            let rgba = image::load_from_memory_with_format(bytes, ImageFormat::Png)?.to_rgba8();
            let (width, height) = rgba.dimensions();
            clipboard
                .set_image(ImageData {
                    width: width as usize,
                    height: height as usize,
                    bytes: Cow::Owned(rgba.into_raw()),
                })
                .context("clipboard rejected image")
        }
        ClipboardItem::File(_) => anyhow::bail!("files cannot be written to the clipboard"),
    }
}
