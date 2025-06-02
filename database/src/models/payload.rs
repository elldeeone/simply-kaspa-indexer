#[derive(Debug, Clone)] // Add other derives as necessary (e.g., for database interaction)
pub struct Payload {
    pub transaction_id: Vec<u8>,
    pub block_hash: Vec<u8>,
    pub block_time: i64,
    pub block_daa_score: i64,
    pub version: i16,          // Or u8 if preferred, DB stores SMALLINT
    pub contract_type_id: i32, // Or u128 if preferred, DB stores INTEGER
    pub sender_address: Option<String>,
    pub raw_payload: Vec<u8>,
} 