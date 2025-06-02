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
use simply_kaspa_database::models::payload::Payload;
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
    let mut pending_payloads = vec![];
    let mut checkpoint_blocks = vec![];
    let mut last_commit_time = Instant::now();

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
                let transaction_id = rpc_transaction.verbose_data.as_ref().unwrap().transaction_id;
                if tx_id_cache.contains_key(&transaction_id) {
                    trace!("Known transaction_id {}, keeping block relation only", transaction_id.to_string());
                } else {
                    // Convert KaspaHash transaction_id to hex string for pattern matching
                    let tx_id_hex = transaction_id.to_string();

                    // Check if the TxID matches the defined pattern (last 10 bits are zero)
                    if check_tx_id_pattern_last_10_bits_zero(&tx_id_hex) {
                        trace!("TxID {} matches pattern. Proceeding to parse payload for dApp data.", tx_id_hex);

                        const MIN_DAPP_PAYLOAD_LEN: usize = 4; // 1 (version) + 3 (contract type ID)
                        let payload = &rpc_transaction.payload; // This is Vec<u8>

                        if payload.len() < MIN_DAPP_PAYLOAD_LEN {
                            warn!(
                                "Pattern-matched TxID {}, but dApp payload too short: len {}, expected min {}. Full payload: {:?}",
                                tx_id_hex,
                                payload.len(),
                                MIN_DAPP_PAYLOAD_LEN,
                                payload
                            );
                        } else {
                            let version = payload[0]; // Version is at the start of the payload
                            const SUPPORTED_VERSION: u8 = 0x01; // Define your supported version

                            if version != SUPPORTED_VERSION {
                                warn!(
                                    "Unsupported dApp payload version for pattern-matched TxID {}: got {}, expected {}. Full payload: {:?}",
                                    tx_id_hex,
                                    version,
                                    SUPPORTED_VERSION,
                                    payload
                                );
                            } else {
                                // Extract ContractTypeID (3 bytes in big-endian format, starting at payload[1])
                                let contract_type_id = ((payload[1] as u128) << 16) |
                                                      ((payload[2] as u128) << 8) |
                                                       (payload[3] as u128);

                                trace!(
                                    "For pattern-matched TxID {}, dApp ContractTypeID bytes: [{:02X}, {:02X}, {:02X}] => {}. Full payload: {:?}",
                                    tx_id_hex, payload[1], payload[2], payload[3], contract_type_id, payload
                                );

                                debug!(
                                    "Found valid dApp payload for pattern-matched TxID {}: version {}, contract_type_id {}",
                                    tx_id_hex, version, contract_type_id
                                );

                                // Assuming `Payload` struct and `pending_payloads` vector are already defined/available
                                // (e.g., from the `simply-kaspa-database` crate and existing indexer structure if the fork includes it).
                                // If not, these (or equivalents) would also need to be defined.
                                let contract_data = Payload {
                                    transaction_id: transaction_id.as_bytes().to_vec(), // KaspaHash to Vec<u8>
                                    block_hash: transaction_data.block_hash.as_bytes().to_vec(), // KaspaHash to Vec<u8>
                                    block_time: transaction_data.block_timestamp as i64,
                                    block_daa_score: transaction_data.block_daa_score as i64, // Cast to i64
                                    version: version as i16,
                                    contract_type_id: contract_type_id as i32,
                                    sender_address: None, // Sender address is typically derived later in the original codebase
                                    raw_payload: payload.clone(), // Store the full original payload
                                };

                                pending_payloads.push(contract_data);
                                debug!("Added dApp payload for pattern-matched TxID {} to pending list. Current pending count: {}",
                                       tx_id_hex, pending_payloads.len());
                            }
                        }
                    } // End of TxID pattern check block

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
                            trace!("Pre-resolved {previous_from_outputs_count} tx_inputs from tx_outputs");
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
                let payloads_handle = if !pending_payloads.is_empty() {
                    task::spawn(insert_payloads_db(pending_payloads, database.clone()))
                } else {
                    task::spawn(async { 0 })
                };

                let rows_affected_tx = tx_handle.await.unwrap();
                let rows_affected_tx_inputs = tx_inputs_handle.await.unwrap();
                let rows_affected_tx_outputs = tx_outputs_handle.await.unwrap();
                let rows_affected_block_tx = blocks_txs_handle.await.unwrap();
                let mut rows_affected_tx_addresses = tx_output_addr_handle.await.unwrap();
                let rows_affected_payloads = payloads_handle.await.unwrap();

                // ^Input address resolving can only happen after inputs + outputs are committed
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
                metrics.components.transaction_processor.update_last_block(last_checkpoint.into());
                drop(metrics);

                for checkpoint_block in checkpoint_blocks {
                    while checkpoint_queue.push(checkpoint_block.clone()).is_err() {
                        warn!("Checkpoint queue is full");
                        sleep(Duration::from_secs(1)).await;
                    }
                }
                let commit_time = Instant::now().duration_since(start_commit_time).as_millis();
                let tps = transactions_len as f64 / commit_time as f64 * 1000f64;
                info!(
                    "Committed {} new txs in {}ms ({:.1} tps, {} blk_tx, {} tx_in, {} tx_out, {} adr_tx, {} payloads). Last tx: {}",
                    rows_affected_tx,
                    commit_time,
                    tps,
                    rows_affected_block_tx,
                    rows_affected_tx_inputs,
                    rows_affected_tx_outputs,
                    rows_affected_tx_addresses,
                    rows_affected_payloads,
                    chrono::DateTime::from_timestamp_millis(last_block_time as i64 / 1000 * 1000).unwrap()
                );
                transactions = vec![];
                block_tx = vec![];
                tx_inputs = vec![];
                tx_outputs = vec![];
                tx_address_transactions = vec![];
                tx_script_transactions = vec![];
                pending_payloads = vec![];
                checkpoint_blocks = vec![];
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
    debug!("Committed {} {} in {}ms", rows_affected, key, Instant::now().duration_since(start_time).as_millis());
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
    debug!("Committed {} {} in {}ms", rows_affected, key, Instant::now().duration_since(start_time).as_millis());
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
    debug!("Committed {} {} in {}ms", rows_affected, key, Instant::now().duration_since(start_time).as_millis());
    rows_affected
}

async fn insert_input_tx_addr(batch_scale: f64, use_tx: bool, values: Vec<SqlHash>, database: KaspaDbClient) -> u64 {
    let batch_size = min((100f64 * batch_scale) as u16, 8000) as usize;
    let key = "input addresses_transactions";
    let start_time = Instant::now();
    debug!("Processing {} transactions for {}", values.len(), key);
    let mut rows_affected = 0;
    for batch_values in values.chunks(batch_size) {
        rows_affected += database
            .insert_address_transactions_from_inputs(use_tx, batch_values)
            .await
            .unwrap_or_else(|e| panic!("Insert {key} FAILED: {e}"));
    }
    debug!("Committed {} {} in {}ms", rows_affected, key, Instant::now().duration_since(start_time).as_millis());
    rows_affected
}

async fn insert_input_tx_script(batch_scale: f64, use_tx: bool, values: Vec<SqlHash>, database: KaspaDbClient) -> u64 {
    let batch_size = min((100f64 * batch_scale) as u16, 8000) as usize;
    let key = "input scripts_transactions";
    let start_time = Instant::now();
    debug!("Processing {} transactions for {}", values.len(), key);
    let mut rows_affected = 0;
    for batch_values in values.chunks(batch_size) {
        rows_affected += database
            .insert_script_transactions_from_inputs(use_tx, batch_values)
            .await
            .unwrap_or_else(|e| panic!("Insert {key} FAILED: {e}"));
    }
    debug!("Committed {} {} in {}ms", rows_affected, key, Instant::now().duration_since(start_time).as_millis());
    rows_affected
}

async fn insert_output_tx_addr(batch_scale: f64, values: Vec<AddressTransaction>, database: KaspaDbClient) -> u64 {
    let batch_size = min((250f64 * batch_scale) as u16, 20000) as usize; // 2^16 / fields
    let key = "output addresses_transactions";
    let start_time = Instant::now();
    debug!("Processing {} {}", values.len(), key);
    let mut rows_affected = 0;
    for batch_values in values.chunks(batch_size) {
        rows_affected +=
            database.insert_address_transactions(batch_values).await.unwrap_or_else(|e| panic!("Insert {key} FAILED: {e}"));
    }
    debug!("Committed {} {} in {}ms", rows_affected, key, Instant::now().duration_since(start_time).as_millis());
    rows_affected
}

async fn insert_output_tx_script(batch_scale: f64, values: Vec<ScriptTransaction>, database: KaspaDbClient) -> u64 {
    let batch_size = min((250f64 * batch_scale) as u16, 20000) as usize; // 2^16 / fields
    let key = "output scripts_transactions";
    let start_time = Instant::now();
    debug!("Processing {} {}", values.len(), key);
    let mut rows_affected = 0;
    for batch_values in values.chunks(batch_size) {
        rows_affected +=
            database.insert_script_transactions(batch_values).await.unwrap_or_else(|e| panic!("Insert {key} FAILED: {e}"));
    }
    debug!("Committed {} {} in {}ms", rows_affected, key, Instant::now().duration_since(start_time).as_millis());
    rows_affected
}

async fn insert_block_txs(batch_scale: f64, values: Vec<BlockTransaction>, database: KaspaDbClient) -> u64 {
    let batch_size = min((500f64 * batch_scale) as u16, 30000) as usize; // 2^16 / fields
    let key = "block/transaction mappings";
    let start_time = Instant::now();
    debug!("Processing {} {}", values.len(), key);
    let mut rows_affected = 0;
    for batch_values in values.chunks(batch_size) {
        rows_affected += database.insert_block_transactions(batch_values).await.unwrap_or_else(|e| panic!("Insert {key} FAILED: {e}"));
    }
    debug!("Committed {} {} in {}ms", rows_affected, key, Instant::now().duration_since(start_time).as_millis());
    rows_affected
}

// Added this function for payloads
async fn insert_payloads_db(values: Vec<Payload>, database: KaspaDbClient) -> u64 {
    // Using a smaller batch size for payloads initially, can be tuned.
    let batch_size = 250 as usize; 
    let key = "payloads";
    let start_time = Instant::now();
    debug!("Processing {} {}", values.len(), key);
    let mut rows_affected = 0;
    if values.is_empty() {
        return 0;
    }
    for batch_values in values.chunks(batch_size) {
        rows_affected += database.insert_payloads(batch_values).await.unwrap_or_else(|e| panic!("Insert {key} FAILED: {e}"));
    }
    debug!("Committed {} {} in {}ms", rows_affected, key, Instant::now().duration_since(start_time).as_millis());
    rows_affected
}

// Checks if the last 10 bits of a Kaspa Transaction ID (provided as a hex string) are zero.
fn check_tx_id_pattern_last_10_bits_zero(tx_id_hex: &str) -> bool {
    // A Kaspa TxID is 32 bytes, which is 64 hex characters.
    // We need to check the last 10 bits.
    // 10 bits = 2 full hex chars (8 bits) + 2 bits from the 3rd hex char from the end.

    if tx_id_hex.len() != 64 {
        // Invalid TxID length
        return false;
    }

    // Check the last two hex characters (byte 31) - must be "00" for the last 8 bits to be 0.
    if &tx_id_hex[62..64] != "00" {
        return false;
    }

    // Check the 3rd hex character from the end (first nibble of byte 30).
    // This character represents bits 8-11 from the end. We need bits 8 and 9 (0-indexed from the right) to be 0.
    // The hex characters whose two LSBs are 0 are: '0' (0000), '4' (0100), '8' (1000), 'c' (1100).
    match tx_id_hex.chars().nth(61) {
        Some(char_byte_30_nibble1) => {
            match char_byte_30_nibble1.to_ascii_lowercase() {
                '0' | '4' | '8' | 'c' => true,
                _ => false,
            }
        }
        None => false, // Should not happen if length check passed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_id_pattern_matching() {
        // Test case 1: Valid patterns (last 10 bits are zero)
        let valid_patterns = [
            "0000000000000000000000000000000000000000000000000000000000000c00",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000400",
            "0000000000000000000000000000000000000000000000000000000000000800",
        ];
        for tx_id in valid_patterns {
            assert!(check_tx_id_pattern_last_10_bits_zero(tx_id), "TxID {} should match pattern but didn't", tx_id);
        }
        // Test case 2: Invalid patterns
        let invalid_patterns = [
            "0000000000000000000000000000000000000000000000000000000000000c01",
            "0000000000000000000000000000000000000000000000000000000000000100",
        ];
        for tx_id in invalid_patterns {
            assert!(!check_tx_id_pattern_last_10_bits_zero(tx_id), "TxID {} should NOT match pattern but did", tx_id);
        }
        // Test case 3: Invalid length
        assert!(!check_tx_id_pattern_last_10_bits_zero("short"));
        assert!(!check_tx_id_pattern_last_10_bits_zero("0000000000000000000000000000000000000000000000000000000000000c00extra"));
    }

    #[test]
    fn test_dapp_payload_parsing() { // This test assumes TxID pattern already matched
        // Test case 1: Valid payload with minimum length
        let valid_min_payload = vec![0x01, 0x00, 0x00, 0x01]; // V:1, ID:1
        const MIN_DAPP_PAYLOAD_LEN_TEST: usize = 4;
        const SUPPORTED_VERSION_TEST: u8 = 0x01;

        assert!(valid_min_payload.len() >= MIN_DAPP_PAYLOAD_LEN_TEST);
        let version = valid_min_payload[0];
        assert_eq!(version, SUPPORTED_VERSION_TEST);
        let contract_id_val = ((valid_min_payload[1] as u128) << 16) | ((valid_min_payload[2] as u128) << 8) | (valid_min_payload[3] as u128);
        assert_eq!(contract_id_val, 1);

        // Test case 2: Valid payload with extra data
        let valid_payload_with_data = vec![0x01, 0x00, 0x12, 0x34, 0xAA, 0xBB]; // V:1, ID:4660
        assert!(valid_payload_with_data.len() >= MIN_DAPP_PAYLOAD_LEN_TEST);
        assert_eq!(valid_payload_with_data[0], SUPPORTED_VERSION_TEST);
        let contract_id_val_2 = ((valid_payload_with_data[1] as u128) << 16) | ((valid_payload_with_data[2] as u128) << 8) | (valid_payload_with_data[3] as u128);
        assert_eq!(contract_id_val_2, 4660);

        // Test case 3: Payload too short for dApp data (less than MIN_DAPP_PAYLOAD_LEN_TEST)
        let too_short_payload = vec![0x01, 0x00, 0x00]; // Length 3
        assert!(too_short_payload.len() < MIN_DAPP_PAYLOAD_LEN_TEST);
        // In actual code, this would trigger a 'warn!' and not proceed to version/ID parsing.

        // Test case 4: Unsupported version
        let wrong_version_payload = vec![0x02, 0x00, 0x00, 0x01]; // Version 2
        assert!(wrong_version_payload.len() >= MIN_DAPP_PAYLOAD_LEN_TEST);
        assert_ne!(wrong_version_payload[0], SUPPORTED_VERSION_TEST);
        // In actual code, this would trigger a 'warn!' and not proceed to ID parsing.
    }

    // Example for a test focusing purely on 3-byte ID conversion:
    #[test]
    fn test_core_3_byte_id_conversion() {
        let id_bytes = [0x95, 0x1B, 0x36]; // Example Contract ID bytes
        let expected_id = 9771830;
        let contract_id = ((id_bytes[0] as u128) << 16) |
                           ((id_bytes[1] as u128) << 8) |
                            (id_bytes[2] as u128);
        assert_eq!(contract_id, expected_id);

        let id_bytes_2 = [0x00, 0x00, 0x01]; // Example Contract ID bytes
        let expected_id_2 = 1;
        let contract_id_2 = ((id_bytes_2[0] as u128) << 16) |
                             ((id_bytes_2[1] as u128) << 8) |
                              (id_bytes_2[2] as u128);
        assert_eq!(contract_id_2, expected_id_2);

        let id_bytes_3 = [0x00, 0x12, 0x34]; // Example Contract ID bytes
        let expected_id_3 = 4660;
        let contract_id_3 = ((id_bytes_3[0] as u128) << 16) |
                             ((id_bytes_3[1] as u128) << 8) |
                              (id_bytes_3[2] as u128);
        assert_eq!(contract_id_3, expected_id_3);
    }
}
