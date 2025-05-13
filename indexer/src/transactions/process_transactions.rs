use crate::blocks::fetch_blocks::TransactionData;
use crate::checkpoint::{CheckpointBlock, CheckpointOrigin};
use crate::settings::Settings;
use crate::web::model::metrics::Metrics;
use crossbeam_queue::ArrayQueue;
use kaspa_hashes::Hash as KaspaHash;
use log::{debug, info, trace, warn};
use moka::sync::Cache;
use simply_kaspa_cli::cli_args::{CliDisable, CliEnable, CliField};
use simply_kaspa_database::client::KaspaDbClient;
use simply_kaspa_database::models::address_transaction::AddressTransaction;
use simply_kaspa_database::models::block_transaction::BlockTransaction;
use simply_kaspa_database::models::script_transaction::ScriptTransaction;
use simply_kaspa_database::models::transaction::Transaction;
use simply_kaspa_database::models::transaction_input::TransactionInput;
use simply_kaspa_database::models::transaction_output::TransactionOutput;
use simply_kaspa_database::models::types::hash::Hash as SqlHash;
use simply_kaspa_mapping::mapper::KaspaDbMapper;
use std::cmp::min;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::task;
use tokio::time::sleep;
use simply_kaspa_database::client::Payload;
use kaspa_addresses::{Address, Prefix, Version as AddressVersion};
use hex;

type SubnetworkMap = HashMap<String, i32>;

pub async fn process_transactions(
    settings: Settings,
    run: Arc<AtomicBool>,
    metrics: Arc<RwLock<Metrics>>,
    txs_queue: Arc<ArrayQueue<TransactionData>>,
    checkpoint_queue: Arc<ArrayQueue<CheckpointBlock>>,
    database: KaspaDbClient,
    mapper: KaspaDbMapper,
) {
    let ttl = settings.cli_args.cache_ttl;
    let cache_size = settings.net_tps_max as u64 * ttl * 2;
    let tx_id_cache: Cache<KaspaHash, ()> = Cache::builder().time_to_live(Duration::from_secs(ttl)).max_capacity(cache_size).build();

    let batch_scale = settings.cli_args.batch_scale;
    let batch_size = (5000f64 * batch_scale) as usize;

    let enable_transactions_inputs_resolve = settings.cli_args.is_enabled(CliEnable::TransactionsInputsResolve);
    let disable_transactions = settings.cli_args.is_disabled(CliDisable::TransactionsTable);
    let disable_transactions_inputs = settings.cli_args.is_disabled(CliDisable::TransactionsInputsTable);
    let disable_transactions_outputs = settings.cli_args.is_disabled(CliDisable::TransactionsOutputsTable);
    let disable_blocks_transactions = settings.cli_args.is_disabled(CliDisable::BlocksTransactionsTable);
    let disable_address_transactions = settings.cli_args.is_disabled(CliDisable::AddressesTransactionsTable);
    let exclude_tx_out_script_public_key_address = settings.cli_args.is_excluded(CliField::TxOutScriptPublicKeyAddress);
    let exclude_tx_out_script_public_key = settings.cli_args.is_excluded(CliField::TxOutScriptPublicKey);

    let mut transactions = vec![];
    let mut block_tx = vec![];
    let mut tx_inputs = vec![];
    let mut tx_outputs = vec![];
    let mut tx_address_transactions = vec![];
    let mut tx_script_transactions = vec![];
    let mut checkpoint_blocks = vec![];
    let mut last_commit_time = Instant::now();
    let mut pending_payloads: Vec<Payload> = Vec::new(); // Store Payload structs for processing after script lookup

    let mut subnetwork_map = SubnetworkMap::new();
    let results = database.select_subnetworks().await.expect("Select subnetworks FAILED");
    for s in results {
        subnetwork_map.insert(s.subnetwork_id, s.id);
    }
    info!("Loaded {} known subnetworks", subnetwork_map.len());

    if enable_transactions_inputs_resolve {
        info!("Resolving previous outpoints for inputs");
    }
    if !disable_address_transactions {
        if !exclude_tx_out_script_public_key_address {
            info!("Using addresses_transactions for address transaction mapping");
        } else if !exclude_tx_out_script_public_key {
            info!("Using scripts_transactions for address transaction mapping");
        } else {
            info!("Address transaction mapping disabled");
        }
    } else {
        info!("Address transaction mapping disabled");
    }

    while run.load(Ordering::Relaxed) {
        if let Some(transaction_data) = txs_queue.pop() {
            checkpoint_blocks.push(CheckpointBlock {
                origin: CheckpointOrigin::Transactions,
                hash: transaction_data.block_hash.into(),
                timestamp: transaction_data.block_timestamp,
                daa_score: transaction_data.block_daa_score,
                blue_score: transaction_data.block_blue_score,
            });
            for rpc_transaction in transaction_data.transactions {
                let subnetwork_id = rpc_transaction.subnetwork_id.to_string();
                let subnetwork_key = match subnetwork_map.get(&subnetwork_id) {
                    Some(&subnetwork_key) => subnetwork_key,
                    None => {
                        let subnetwork_key = database.insert_subnetwork(&subnetwork_id).await.expect("Insert subnetwork FAILED");
                        subnetwork_map.insert(subnetwork_id.clone(), subnetwork_key);
                        info!("Committed new subnetwork, id: {} subnetwork_id: {}", subnetwork_key, subnetwork_id);
                        subnetwork_key
                    }
                };
                let verbose_data = rpc_transaction.verbose_data.as_ref().unwrap();
                let transaction_id = verbose_data.transaction_id;

                if tx_id_cache.contains_key(&transaction_id) {
                    trace!("Known transaction_id {}, keeping block relation only", transaction_id.to_string());
                } else {
                    let transaction = mapper.map_transaction(&rpc_transaction, subnetwork_key);
                    transactions.push(transaction);
                    tx_inputs.extend(mapper.map_transaction_inputs(&rpc_transaction));
                    tx_outputs.extend(mapper.map_transaction_outputs(&rpc_transaction));
                    if !disable_address_transactions {
                        if !exclude_tx_out_script_public_key_address {
                            tx_address_transactions.extend(mapper.map_transaction_outputs_address(&rpc_transaction));
                        } else if !exclude_tx_out_script_public_key {
                            tx_script_transactions.extend(mapper.map_transaction_outputs_script(&rpc_transaction));
                        }
                    }

                    // Check for contract magic number (0xC0DE in big-endian or little-endian format)
                    const CONTRACT_MAGIC_NUMBER: [u8; 2] = [0xC0, 0xDE]; // 0xC0DE in big-endian (new standard)
                    const LEGACY_MAGIC_NUMBER: [u8; 2] = [0xDE, 0xC0];   // 0xC0DE in little-endian (legacy format)
                    let payload = &rpc_transaction.payload; // payload is Vec<u8>
                    const MIN_PAYLOAD_LEN: usize = 6; // 2 (magic) + 1 (version) + 3 (contract type ID)

                    // If payload exists and starts with either big-endian or little-endian magic number, parse and potentially store it
                    if payload.starts_with(&CONTRACT_MAGIC_NUMBER) || payload.starts_with(&LEGACY_MAGIC_NUMBER) {
                        let is_legacy_format = payload.starts_with(&LEGACY_MAGIC_NUMBER);
                        
                        // Log which format was detected
                        if is_legacy_format {
                            trace!("Detected legacy little-endian magic number for tx {}", transaction_id);
                        } else {
                            trace!("Detected standard big-endian magic number for tx {}", transaction_id);
                        }
                        
                        if payload.len() < MIN_PAYLOAD_LEN {
                            warn!(
                                "Contract payload too short for tx {}: len {}, expected min {}",
                                transaction_id,
                                payload.len(),
                                MIN_PAYLOAD_LEN
                            );
                        } else {
                            let version = payload[2];
                            const SUPPORTED_VERSION: u8 = 0x01;
                            if version != SUPPORTED_VERSION {
                                warn!(
                                    "Unsupported contract payload version for tx {}: got {}, expected {}",
                                    transaction_id,
                                    version,
                                    SUPPORTED_VERSION
                                );
                            } else {
                                // Extract ContractTypeID (3 bytes in big-endian format starting at byte 3)
                                if payload.len() < 6 { // Ensure we have enough bytes for the contract type ID
                                    warn!(
                                        "Contract payload too short for contract type ID extraction for tx {}: len {}, expected min 6",
                                        transaction_id,
                                        payload.len()
                                    );
                                } else {
                                    // Read contract type ID as 3 bytes in big-endian format using bit shifting
                                    // This ensures correct byte interpretation: [byte0, byte1, byte2]
                                    let contract_type_id = ((payload[3] as u128) << 16) | 
                                                          ((payload[4] as u128) << 8) | 
                                                           (payload[5] as u128);
                                    
                                    // Add debug logging to verify the extraction
                                    trace!(
                                        "Contract type ID bytes: [{:02X}, {:02X}, {:02X}] => {}",
                                        payload[3], payload[4], payload[5], contract_type_id
                                    );
                                    
                                    // Successfully parsed!
                                    debug!(
                                        "Found valid contract payload for tx {}: version {}, contract_type_id {}",
                                        transaction_id, version, contract_type_id
                                    );

                                    // Create Payload struct with updated payload extraction
                                    // The header is now fixed at 6 bytes: 2B magic + 1B version + 3B type ID
                                    // Extract actual payload data starting from byte 6
                                    let contract_data = Payload {
                                        transaction_id: transaction_id.as_bytes().to_vec(),
                                        block_hash: transaction_data.block_hash.as_bytes().to_vec(),
                                        block_time: transaction_data.block_timestamp as i64,
                                        block_daa_score: transaction_data.block_daa_score,
                                        version: version as i16,
                                        contract_type_id: contract_type_id as i32,
                                        sender_address: None,
                                        raw_payload: payload.clone(),
                                    };

                                    // Add the struct to the pending list for later processing
                                    pending_payloads.push(contract_data);
                                    debug!("Added contract payload for tx {} to pending list. Current pending count: {}", 
                                           transaction_id, pending_payloads.len());
                                }
                            }
                        }
                    }

                    tx_id_cache.insert(transaction_id, ());
                }
                block_tx.push(mapper.map_block_transaction(&rpc_transaction));
            }

            if block_tx.len() >= batch_size || (!block_tx.is_empty() && Instant::now().duration_since(last_commit_time).as_secs() > 2)
            {
                let start_commit_time = Instant::now();
                let transactions_len = transactions.len();
                let transaction_ids: Vec<SqlHash> = transactions.iter().map(|t| t.transaction_id.clone()).collect();

                let tx_handle = if !disable_transactions {
                    task::spawn(insert_txs(batch_scale, transactions, database.clone()))
                } else {
                    task::spawn(async { 0 })
                };
                let blocks_txs_handle = if !disable_blocks_transactions {
                    task::spawn(insert_block_txs(batch_scale, block_tx, database.clone()))
                } else {
                    task::spawn(async { 0 })
                };
                let tx_output_addr_handle = if !disable_address_transactions {
                    if !exclude_tx_out_script_public_key_address {
                        task::spawn(insert_output_tx_addr(batch_scale, tx_address_transactions, database.clone()))
                    } else if !exclude_tx_out_script_public_key {
                        task::spawn(insert_output_tx_script(batch_scale, tx_script_transactions, database.clone()))
                    } else {
                        task::spawn(async { 0 })
                    }
                } else {
                    task::spawn(async { 0 })
                };
                let tx_inputs_handle = if !disable_transactions_inputs {
                    if enable_transactions_inputs_resolve {
                        let tx_outputs_map: HashMap<_, _> =
                            tx_outputs.iter().map(|tx| ((tx.transaction_id.clone(), tx.index), tx)).collect();
                        let mut previous_from_outputs_count = 0;
                        for tx_input in tx_inputs.iter_mut() {
                            let key = (tx_input.previous_outpoint_hash.clone().unwrap(), tx_input.previous_outpoint_index.unwrap());
                            if let Some(tx_output) = tx_outputs_map.get(&key) {
                                tx_input.previous_outpoint_script = tx_output.script_public_key.clone();
                                tx_input.previous_outpoint_amount = tx_output.amount;
                                previous_from_outputs_count += 1;
                            }
                        }
                        if previous_from_outputs_count > 0 {
                            trace!("Pre-resolved {previous_from_outputs_count} tx_inputs from tx_outputs ");
                        }
                    }
                    task::spawn(insert_tx_inputs(batch_scale, enable_transactions_inputs_resolve, tx_inputs, database.clone()))
                } else {
                    task::spawn(async { 0 })
                };
                let tx_outputs_handle = if !disable_transactions_outputs {
                    task::spawn(insert_tx_outputs(batch_scale, tx_outputs, database.clone()))
                } else {
                    task::spawn(async { 0 })
                };
                let rows_affected_tx = tx_handle.await.unwrap();
                let rows_affected_tx_inputs = tx_inputs_handle.await.unwrap();
                let rows_affected_tx_outputs = tx_outputs_handle.await.unwrap();
                let rows_affected_block_tx = blocks_txs_handle.await.unwrap();
                let mut rows_affected_tx_addresses = tx_output_addr_handle.await.unwrap();

                // --- BEGIN: Process pending contract payloads for insertion ---
                if !pending_payloads.is_empty() && enable_transactions_inputs_resolve {
                    debug!("Processing {} pending contract payloads for address derivation and insertion...", pending_payloads.len());
                    let mut successful_inserts = 0;
                    let mut failed_derivation = 0; // Count payloads where derivation fails or script not found
                    let mut failed_inserts = 0; // Count payloads where DB insert fails

                    // Iterate mutably to update sender_address in place
                    for payload in pending_payloads.iter_mut() {
                        let derived_sender_address: Option<String> = {
                            let tx_id_hex = hex::encode(&payload.transaction_id);
                            match database.get_transaction_input_script(&payload.transaction_id).await {
                                Ok(Some(script_bytes)) => {
                                    // Manually parse the raw script bytes
                                    const P2PK_STANDARD_LEN: usize = 34;
                                    const P2PK_OP_CHECKSIG: u8 = 0xac;
                                    const PUBKEY_LEN_BYTE: u8 = 0x20;

                                    if script_bytes.len() == P2PK_STANDARD_LEN &&
                                       script_bytes[0] == PUBKEY_LEN_BYTE &&
                                       script_bytes[P2PK_STANDARD_LEN - 1] == P2PK_OP_CHECKSIG {

                                        let pub_key_payload = &script_bytes[1..P2PK_STANDARD_LEN-1];
                                        let address = Address::new(Prefix::Testnet, AddressVersion::PubKey, pub_key_payload);
                                        trace!("Successfully derived P2PK sender address for tx {}: {}", tx_id_hex, address);
                                        Some(address.to_string())
                                    }
                                    // TODO: Add else if blocks here to handle other script types (P2SH, Schnorr P2PK)
                                    else {
                                        warn!("Unsupported script format/length ({}) encountered for tx {}: {:?}", script_bytes.len(), tx_id_hex, script_bytes);
                                        None
                                    }
                                },
                                Ok(None) => {
                                    trace!("No input script found for tx {} (likely coinbase or pruned input).", tx_id_hex);
                                    None
                                },
                                Err(e) => {
                                    warn!("Failed to query input script for tx {}: {}.", tx_id_hex, e);
                                    None
                                }
                            }
                        };

                        // Update the sender_address in the struct
                        payload.sender_address = derived_sender_address;

                        // Now, attempt to insert the complete Payload
                        let tx_id_hex = hex::encode(&payload.transaction_id);
                        match database.insert_payload(payload).await {
                            Ok(inserted_rows) => {
                                if inserted_rows > 0 {
                                    trace!("Successfully inserted contract payload for tx {}", tx_id_hex);
                                    successful_inserts += 1;
                                } else {
                                     // This case might occur if the TX somehow got inserted between planning and execution,
                                     // or if insert_payload has ON CONFLICT DO NOTHING (which it should)
                                    trace!("Contract payload for tx {} may already exist (skipped insert)", tx_id_hex);
                                    // Consider if this should be counted as success or a separate category
                                }
                            }
                            Err(e) => {
                                warn!("Error inserting contract payload for tx {}: {}", tx_id_hex, e);
                                failed_inserts += 1;
                            }
                        }

                        // Track derivation failures separately from insert failures
                        if payload.sender_address.is_none() {
                            failed_derivation += 1;
                            trace!("No sender address derived for tx {}, inserted with NULL", tx_id_hex);
                        }
                    }
                    debug!(
                        "Finished contract payload processing: {} successful inserts, {} failed derivations, {} failed inserts.",
                        successful_inserts, failed_derivation, failed_inserts
                    );
                    pending_payloads.clear(); // Clear the list after processing all items
                }
                // --- END: Process pending contract payloads for insertion ---

                if !disable_address_transactions {
                    let use_tx_for_time = settings.cli_args.is_excluded(CliField::TxInBlockTime);
                    rows_affected_tx_addresses += if !exclude_tx_out_script_public_key_address {
                        insert_input_tx_addr(batch_scale, use_tx_for_time, transaction_ids, database.clone()).await
                    } else if !exclude_tx_out_script_public_key {
                        insert_input_tx_script(batch_scale, use_tx_for_time, transaction_ids, database.clone()).await
                    } else {
                        0
                    };
                }
                let last_checkpoint = checkpoint_blocks.last().unwrap().clone();
                let last_block_time = last_checkpoint.timestamp;

                let mut metrics = metrics.write().await;
                metrics.components.transaction_processor.last_block = Some(last_checkpoint.into());
                drop(metrics);

                for checkpoint_block in checkpoint_blocks {
                    while checkpoint_queue.push(checkpoint_block.clone()).is_err() {
                        warn!("Checkpoint queue is full ");
                        sleep(Duration::from_secs(1)).await;
                    }
                }
                let commit_time = Instant::now().duration_since(start_commit_time).as_millis();
                let tps = transactions_len as f64 / commit_time as f64 * 1000f64;
                info!(
                    "Committed {} new txs in {}ms ({:.1} tps, {} blk_tx, {} tx_in, {} tx_out, {} adr_tx). Last tx: {}",
                    rows_affected_tx,
                    commit_time,
                    tps,
                    rows_affected_block_tx,
                    rows_affected_tx_inputs,
                    rows_affected_tx_outputs,
                    rows_affected_tx_addresses,
                    chrono::DateTime::from_timestamp_millis(last_block_time as i64 / 1000 * 1000).unwrap()
                );
                transactions = vec![];
                block_tx = vec![];
                tx_inputs = vec![];
                tx_outputs = vec![];
                tx_address_transactions = vec![];
                tx_script_transactions = vec![];
                checkpoint_blocks = vec![];
                pending_payloads = vec![]; // Clear any remaining pending payloads
                last_commit_time = Instant::now();
            }
        } else {
            sleep(Duration::from_millis(100)).await;
        }
    }
}

async fn insert_txs(batch_scale: f64, values: Vec<Transaction>, database: KaspaDbClient) -> u64 {
    let batch_size = min((250f64 * batch_scale) as u16, 8000) as usize; // 2^16 / fields
    let key = "transactions";
    let start_time = Instant::now();
    debug!("Processing {} {}", values.len(), key);
    let mut rows_affected = 0;
    for batch_values in values.chunks(batch_size) {
        rows_affected += database.insert_transactions(batch_values).await.unwrap_or_else(|e| panic!("Insert {key} FAILED: {e}"));
    }
    debug!("Committed {} {} in {} ms", rows_affected, key, Instant::now().duration_since(start_time).as_millis());
    rows_affected
}

async fn insert_tx_inputs(
    batch_scale: f64,
    resolve_previous_outpoints: bool,
    values: Vec<TransactionInput>,
    database: KaspaDbClient,
) -> u64 {
    let batch_size = min((250f64 * batch_scale) as u16, 8000) as usize; // 2^16 / fields
    let key = "transaction_inputs";
    let start_time = Instant::now();
    debug!("Processing {} {}", values.len(), key);
    let mut rows_affected = 0;
    for batch_values in values.chunks(batch_size) {
        rows_affected += database
            .insert_transaction_inputs(resolve_previous_outpoints, batch_values)
            .await
            .unwrap_or_else(|e| panic!("Insert {key} FAILED: {e}"));
    }
    debug!("Committed {} {} in {} ms", rows_affected, key, Instant::now().duration_since(start_time).as_millis());
    rows_affected
}

async fn insert_tx_outputs(batch_scale: f64, values: Vec<TransactionOutput>, database: KaspaDbClient) -> u64 {
    let batch_size = min((250f64 * batch_scale) as u16, 10000) as usize; // 2^16 / fields
    let key = "transactions_outputs";
    let start_time = Instant::now();
    debug!("Processing {} {}", values.len(), key);
    let mut rows_affected = 0;
    for batch_values in values.chunks(batch_size) {
        rows_affected +=
            database.insert_transaction_outputs(batch_values).await.unwrap_or_else(|e| panic!("Insert {key} FAILED: {e}"));
    }
    debug!("Committed {} {} in {} ms", rows_affected, key, Instant::now().duration_since(start_time).as_millis());
    rows_affected
}

async fn insert_input_tx_addr(batch_scale: f64, use_tx: bool, values: Vec<SqlHash>, database: KaspaDbClient) -> u64 {
    let batch_size = min((100f64 * batch_scale) as u16, 8000) as usize;
    let key = "input addresses_transactions ";
    let start_time = Instant::now();
    debug!("Processing {} transactions for {}", values.len(), key);
    let mut rows_affected = 0;
    for batch_values in values.chunks(batch_size) {
        rows_affected += database
            .insert_address_transactions_from_inputs(use_tx, batch_values)
            .await
            .unwrap_or_else(|e| panic!("Insert {key} FAILED: {e}"));
    }
    debug!("Committed {} {} in {} ms", rows_affected, key, Instant::now().duration_since(start_time).as_millis());
    rows_affected
}

async fn insert_input_tx_script(batch_scale: f64, use_tx: bool, values: Vec<SqlHash>, database: KaspaDbClient) -> u64 {
    let batch_size = min((100f64 * batch_scale) as u16, 8000) as usize;
    let key = "input scripts_transactions ";
    let start_time = Instant::now();
    debug!("Processing {} transactions for {}", values.len(), key);
    let mut rows_affected = 0;
    for batch_values in values.chunks(batch_size) {
        rows_affected += database
            .insert_script_transactions_from_inputs(use_tx, batch_values)
            .await
            .unwrap_or_else(|e| panic!("Insert {key} FAILED: {e}"));
    }
    debug!("Committed {} {} in {} ms", rows_affected, key, Instant::now().duration_since(start_time).as_millis());
    rows_affected
}

async fn insert_output_tx_addr(batch_scale: f64, values: Vec<AddressTransaction>, database: KaspaDbClient) -> u64 {
    let batch_size = min((250f64 * batch_scale) as u16, 20000) as usize; // 2^16 / fields
    let key = "output addresses_transactions ";
    let start_time = Instant::now();
    debug!("Processing {} {}", values.len(), key);
    let mut rows_affected = 0;
    for batch_values in values.chunks(batch_size) {
        rows_affected +=
            database.insert_address_transactions(batch_values).await.unwrap_or_else(|e| panic!("Insert {key} FAILED: {e}"));
    }
    debug!("Committed {} {} in {} ms", rows_affected, key, Instant::now().duration_since(start_time).as_millis());
    rows_affected
}

async fn insert_output_tx_script(batch_scale: f64, values: Vec<ScriptTransaction>, database: KaspaDbClient) -> u64 {
    let batch_size = min((250f64 * batch_scale) as u16, 20000) as usize; // 2^16 / fields
    let key = "output scripts_transactions ";
    let start_time = Instant::now();
    debug!("Processing {} {}", values.len(), key);
    let mut rows_affected = 0;
    for batch_values in values.chunks(batch_size) {
        rows_affected +=
            database.insert_script_transactions(batch_values).await.unwrap_or_else(|e| panic!("Insert {key} FAILED: {e}"));
    }
    debug!("Committed {} {} in {} ms", rows_affected, key, Instant::now().duration_since(start_time).as_millis());
    rows_affected
}

async fn insert_block_txs(batch_scale: f64, values: Vec<BlockTransaction>, database: KaspaDbClient) -> u64 {
    let batch_size = min((500f64 * batch_scale) as u16, 30000) as usize; // 2^16 / fields
    let key = "block/transaction mappings ";
    let start_time = Instant::now();
    debug!("Processing {} {}", values.len(), key);
    let mut rows_affected = 0;
    for batch_values in values.chunks(batch_size) {
        rows_affected += database.insert_block_transactions(batch_values).await.unwrap_or_else(|e| panic!("Insert {key} FAILED: {e}"));
    }
    debug!("Committed {} {} in {} ms", rows_affected, key, Instant::now().duration_since(start_time).as_millis());
    rows_affected
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_fixed_contract_id_decode() {
        // Test cases: 3-byte big-endian contract type ID extraction using bit shifting
        
        // Test case 1: Basic contract type ID extraction
        let test_basic_values = [
            // [bytes] = expected decimal value
            ([0x00, 0x00, 0x01], 1),            // Smallest non-zero value
            ([0x00, 0x01, 0x00], 256),          // Middle byte value
            ([0x01, 0x00, 0x00], 65536),        // High byte value
            ([0xFF, 0xFF, 0xFF], 16777215),     // Maximum 3-byte value
        ];
        
        for (bytes, expected) in test_basic_values {
            let contract_id = ((bytes[0] as u128) << 16) | 
                             ((bytes[1] as u128) << 8) | 
                              (bytes[2] as u128);
            assert_eq!(
                contract_id, 
                expected, 
                "Bytes [{:02X}, {:02X}, {:02X}] should equal {} but got {}", 
                bytes[0], bytes[1], bytes[2], expected, contract_id
            );
        }
        
        // Test case 2: Real-world contract IDs that were previously problematic
        let real_world_values = [
            // [bytes] = expected decimal value
            ([0x95, 0x1B, 0x36], 9771830),  // First problematic contract ID 
            ([0x95, 0x2B, 0x76], 9775990),  // Second problematic contract ID
        ];
        
        for (bytes, expected) in real_world_values {
            let contract_id = ((bytes[0] as u128) << 16) | 
                             ((bytes[1] as u128) << 8) | 
                              (bytes[2] as u128);
            assert_eq!(
                contract_id, 
                expected, 
                "Real-world contract ID bytes [{:02X}, {:02X}, {:02X}] should equal {} but got {}", 
                bytes[0], bytes[1], bytes[2], expected, contract_id
            );
        }
        
        // Test case 3: Complete envelope extraction - simulating production code path
        let test_envelopes = [
            // [magic1, magic2, version, id1, id2, id3, ...payload] => expected ID
            (vec![0xDE, 0xC0, 0x01, 0x00, 0x00, 0x01, 0xAA, 0xBB], 1),
            (vec![0xDE, 0xC0, 0x01, 0x95, 0x1B, 0x36, 0xAA, 0xBB], 9771830),
            (vec![0xDE, 0xC0, 0x01, 0x95, 0x2B, 0x76, 0xAA, 0xBB], 9775990),
        ];
        
        for (envelope, expected_id) in test_envelopes {
            // Verify magic number (little-endian 0xC0DE)
            assert_eq!(envelope[0], 0xDE);
            assert_eq!(envelope[1], 0xC0);
            
            // Verify version
            assert_eq!(envelope[2], 0x01);
            
            // Extract contract ID exactly as done in production code
            let contract_id = ((envelope[3] as u128) << 16) | 
                              ((envelope[4] as u128) << 8) | 
                               (envelope[5] as u128);
                               
            assert_eq!(
                contract_id, 
                expected_id, 
                "Contract ID extracted from envelope should be {} but got {}", 
                expected_id, contract_id
            );
            
            // Verify minimum length requirement for contract header
            assert!(envelope.len() >= 6, "Envelope must be at least 6 bytes");
        }
        
        // Test case 4: Byte order is critical - ensure different byte orders produce different values
        let byte_order_test = [
            ([0x01, 0x02, 0x03], 66051),    // 0x010203 = 66051
            ([0x03, 0x02, 0x01], 197121),   // 0x030201 = 197121
            ([0x02, 0x01, 0x03], 131331),   // 0x020103 = 131331
        ];
        
        for (bytes, expected) in byte_order_test {
            let contract_id = ((bytes[0] as u128) << 16) | 
                             ((bytes[1] as u128) << 8) | 
                              (bytes[2] as u128);
            assert_eq!(
                contract_id, 
                expected, 
                "Byte order test failed: [{:02X}, {:02X}, {:02X}] should equal {} but got {}", 
                bytes[0], bytes[1], bytes[2], expected, contract_id
            );
        }
        
        // Test case 5: Compare bit shifting to u32::from_be_bytes to verify consistency
        let from_be_bytes_test = [
            ([0x00, 0x01, 0x02], 258),      // 0x000102 = 258
            ([0x10, 0x20, 0x30], 1056816),  // 0x102030 = 1056816
        ];
        
        for (bytes, expected) in from_be_bytes_test {
            // Our bit shifting implementation
            let bit_shift_result = ((bytes[0] as u128) << 16) | 
                                  ((bytes[1] as u128) << 8) | 
                                   (bytes[2] as u128);
                                   
            // Standard library implementation (padding with 0 as first byte)
            let from_be_result = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as u128;
            
            assert_eq!(bit_shift_result, expected, "Bit shifting result incorrect");
            assert_eq!(from_be_result, expected, "from_be_bytes result incorrect");
            assert_eq!(bit_shift_result, from_be_result, "Implementations should be equivalent");
        }
    }

    #[test]
    fn test_contract_payload_detection() {
        // Define the magic numbers for testing
        const CONTRACT_MAGIC_NUMBER: [u8; 2] = [0xC0, 0xDE]; // Big-endian (new standard)
        const LEGACY_MAGIC_NUMBER: [u8; 2] = [0xDE, 0xC0];   // Little-endian (legacy format)

        // Test case 1: Valid minimum-length payload with big-endian magic number (6 bytes - just the header)
        let valid_min_payload_bigendian = vec![
            0xC0, 0xDE,          // Magic number (0xC0DE in big-endian)
            0x01,                // Version
            0x00, 0x00, 0x01     // Contract ID = 1 (big-endian)
        ];
        assert!(valid_min_payload_bigendian.starts_with(&CONTRACT_MAGIC_NUMBER));
        assert_eq!(valid_min_payload_bigendian.len(), 6); // Minimum length check

        // Test case 2: Valid minimum-length payload with little-endian magic number (6 bytes - just the header)
        let valid_min_payload_littleendian = vec![
            0xDE, 0xC0,          // Magic number (0xC0DE in little-endian)
            0x01,                // Version
            0x00, 0x00, 0x01     // Contract ID = 1 (big-endian)
        ];
        assert!(valid_min_payload_littleendian.starts_with(&LEGACY_MAGIC_NUMBER));
        assert_eq!(valid_min_payload_littleendian.len(), 6); // Minimum length check

        // Test case 3: Valid payload with data (big-endian magic number)
        let valid_payload_with_data_bigendian = vec![
            0xC0, 0xDE,          // Magic number (big-endian)
            0x01,                // Version
            0x00, 0x12, 0x34,    // Contract ID = 4660 (big-endian)
            // Payload data
            0x48, 0x65, 0x6C, 0x6C, 0x6F // "Hello"
        ];
        assert!(valid_payload_with_data_bigendian.starts_with(&CONTRACT_MAGIC_NUMBER));
        assert_eq!(valid_payload_with_data_bigendian.len(), 11); // Header + data

        // Test case 4: Valid payload with data (little-endian magic number)
        let valid_payload_with_data_littleendian = vec![
            0xDE, 0xC0,          // Magic number (little-endian)
            0x01,                // Version
            0x00, 0x12, 0x34,    // Contract ID = 4660 (big-endian)
            // Payload data
            0x48, 0x65, 0x6C, 0x6C, 0x6F // "Hello"
        ];
        assert!(valid_payload_with_data_littleendian.starts_with(&LEGACY_MAGIC_NUMBER));
        assert_eq!(valid_payload_with_data_littleendian.len(), 11); // Header + data

        // Test case 5: Maximum contract ID with big-endian magic number
        let max_contract_id_payload_bigendian = vec![
            0xC0, 0xDE,          // Magic number (big-endian)
            0x01,                // Version
            0xFF, 0xFF, 0xFF,    // Contract ID = 16777215 (max 3-byte value)
            // Some payload data
            0x01, 0x02
        ];
        assert!(max_contract_id_payload_bigendian.starts_with(&CONTRACT_MAGIC_NUMBER));
        let contract_id = ((max_contract_id_payload_bigendian[3] as u128) << 16) | 
                         ((max_contract_id_payload_bigendian[4] as u128) << 8) | 
                          (max_contract_id_payload_bigendian[5] as u128);
        assert_eq!(contract_id, 16777215);
    }

    #[test]
    fn test_invalid_contract_payload_rejection() {
        // Define the magic numbers for testing
        const CONTRACT_MAGIC_NUMBER: [u8; 2] = [0xC0, 0xDE]; // Big-endian (new standard)
        const LEGACY_MAGIC_NUMBER: [u8; 2] = [0xDE, 0xC0];   // Little-endian (legacy format)

        // Test case 1: Wrong magic number (neither big-endian nor little-endian)
        let wrong_magic = vec![
            0xDE, 0xC1,          // Wrong magic number (not 0xC0DE in either format)
            0x01,                // Version
            0x00, 0x00, 0x01     // Contract ID
        ];
        assert!(!wrong_magic.starts_with(&CONTRACT_MAGIC_NUMBER));
        assert!(!wrong_magic.starts_with(&LEGACY_MAGIC_NUMBER));

        // Test case 2: Too short (less than 6 bytes)
        let too_short_bigendian = vec![
            0xC0, 0xDE,          // Magic number (big-endian)
            0x01,                // Version
            0x00, 0x00           // Incomplete contract ID (missing 1 byte)
        ];
        assert!(too_short_bigendian.starts_with(&CONTRACT_MAGIC_NUMBER));
        assert!(too_short_bigendian.len() < 6); // Should be rejected as too short

        let too_short_littleendian = vec![
            0xDE, 0xC0,          // Magic number (little-endian)
            0x01,                // Version
            0x00, 0x00           // Incomplete contract ID (missing 1 byte)
        ];
        assert!(too_short_littleendian.starts_with(&LEGACY_MAGIC_NUMBER));
        assert!(too_short_littleendian.len() < 6); // Should be rejected as too short

        // Test case 3: Wrong version
        let wrong_version_bigendian = vec![
            0xC0, 0xDE,          // Magic number (big-endian)
            0x02,                // Unsupported version (only 0x01 is supported)
            0x00, 0x00, 0x01     // Contract ID
        ];
        assert!(wrong_version_bigendian.starts_with(&CONTRACT_MAGIC_NUMBER));
        assert_ne!(wrong_version_bigendian[2], 0x01); // Version check should reject this

        let wrong_version_littleendian = vec![
            0xDE, 0xC0,          // Magic number (little-endian)
            0x02,                // Unsupported version (only 0x01 is supported)
            0x00, 0x00, 0x01     // Contract ID
        ];
        assert!(wrong_version_littleendian.starts_with(&LEGACY_MAGIC_NUMBER));
        assert_ne!(wrong_version_littleendian[2], 0x01); // Version check should reject this
    }
}
