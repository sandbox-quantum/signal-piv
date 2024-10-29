// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    io::{BufReader, BufWriter, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
};

use anyhow::{anyhow, bail, Context};
use log::{debug, error, info};
use yubikey::{piv, YubiKey};



fn main() -> anyhow::Result<()> {
    env_logger::init();

    let unix_listener = initialize_uds()?;

    let mut yubikey = YubiKey::open()
        .context("Failed to open yubikey device")
        .unwrap();

    let transaction = yubikey
        .begin_transaction()
        .context("Failed to create transaction")?;

    loop {
        let (unix_stream, _socket_address) = unix_listener
            .accept()
            .context("Failed at accepting a connection on the unix listener")?;
        handle_stream(&transaction, unix_stream)?;
    }
}

fn initialize_uds() -> anyhow::Result<UnixListener> {
    info!("Starting UDS listener");
    let socket_path = "/tmp/signal-piv.sock";

    if std::fs::metadata(socket_path).is_ok() {
        info!("A socket is already present. Deleting...");
        std::fs::remove_file(socket_path)
            .with_context(|| format!("could not delete previous socket at {:?}", socket_path))?;
    }

    UnixListener::bind(socket_path).context("Could not create the unix socket")
}

fn handle_stream(
    transaction: &yubikey::Transaction,
    unix_stream: UnixStream,
) -> anyhow::Result<()> {
    debug!("Handling new connection");

    let mut buf = [0u8; 8192];
    let mut reader = BufReader::new(
        unix_stream
            .try_clone()
            .context("Failed to duplicate handle on UDS")?,
    );
    let mut writer = BufWriter::new(unix_stream);
    loop {
        let mut command_len_buf = [0u8; 4];
        if let Err(err) = reader.read_exact(&mut command_len_buf) {
            error!("Failed to read command length: {err}");
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                break;
            }
            break;
        }
        let command_len = u32::from_le_bytes(command_len_buf) as usize;
        let mut command_buf = &mut buf[..command_len];
        if let Err(err) = reader.read_exact(&mut command_buf) {
            error!("Failed to read command: {err}");
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                break;
            }
            break;
        }
        let command = match String::from_utf8(command_buf.to_vec()) {
            Ok(command) => command,
            Err(err) => {
                error!("Failed to parse command: {err}");
                break;
            }
        };

        let response = match handle_command(transaction, &command) {
            Ok(agreement) => format!("success {}", hex::encode(&agreement)),
            Err(err) => {
                error!("Failed to handle command: {err}");
                format!("error {err}")
            }
        };
        log::info!("[sending] {response}");
        let response = response.into_bytes();
        let len = u32::try_from(response.len()).unwrap();
        if let Err(err) = writer.write_all(&len.to_le_bytes()) {
            error!("Failed to write response len: {err}");
            break;
        }
        if let Err(err) = writer.write_all(&response) {
            error!("Failed to write response: {err}");
            break;
        }
        break;
    }

    Ok(())
}

fn handle_command(transaction: &yubikey::Transaction, command: &str) -> anyhow::Result<Vec<u8>> {
    debug!("Handling command '{command}'");
    let (command_code, command_body) = command.split_once(" ").ok_or_else(|| anyhow!("Failed to get command_code: {command}"))?;
    match command_code {
        "calculate_agreement" => handle_calculate_agreement(transaction, command_body).context("handling calculate_agreement command"),
        _ => bail!("Unknown command: {command_code}"),
    }
}

fn handle_calculate_agreement(transaction: &yubikey::Transaction, command_body: &str) -> anyhow::Result<Vec<u8>> {
    let (key_slot, command_body) = command_body.split_once(" ").ok_or(anyhow!("Failed to parse command: missing 'our_key'"))?;

    let (their_key, command_body) = command_body.split_once(" ").ok_or(anyhow!("Failed to parse command: missing 'their_key'"))?;

    if command_body != "" {
        bail!("Failed to parse command, unexpected data at the end of the body: {command_body}")
    }
    
    let key_slot = match key_slot {
        "R1" => piv::SlotId::Retired(piv::RetiredSlotId::R1),
        "R2" => piv::SlotId::Retired(piv::RetiredSlotId::R2),
        other => bail!("Invalid slot id: {other}"),
    };

    let their_key = hex::decode(&their_key).context("Failed to parse 'their_key'")?;
    if their_key.len() != 33 {
        bail!(
            "Invalid length for 'their_key'. Expected '33', got: {}",
            their_key.len()
        );
    }
    let agreement = piv::decrypt_data_with_transaction(
        transaction,
        &their_key[1..],
        yubikey::piv::AlgorithmId::X25519,
        key_slot,
    )
    .map_err(|err| anyhow!("{err}"))
    .context("Yubikey failed to calculate agreement")?;
    Ok(agreement.to_vec())
}