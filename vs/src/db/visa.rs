use capnp;

use redis::AsyncCommands;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use tracing::debug;

use ::zpr::vsapi::v1 as vsapi;

use zpr::vsapi_types::Visa;
use zpr::vsapi_types_writers::WriteTo;

use crate::db::{Handle, gen_timestamp};
use crate::error::DBError;
use crate::logging::targets::REDIS;

const KEY_VISA: &str = "visa";
const KEY_NEXT_VISA_ID: &str = "visa:next_visa_id";
const KEY_VISAS: &str = "visas";

pub struct VisaRepo {
    db: Handle,
}

impl VisaRepo {
    pub fn new(db: &Handle) -> Self {
        // TODO: Could sanity check db state here.
        VisaRepo { db: db.clone() }
    }

    pub async fn get_next_visa_id(&self) -> Result<u64, DBError> {
        let mut conn = self.db.conn.clone();
        let next_id: u64 = conn.incr(KEY_NEXT_VISA_ID, 1).await?;
        Ok(next_id)
    }

    /// Store the visa in the database.  Does not update information about who needs
    /// this visa.
    ///
    /// Updates:
    /// - visas:<ID>
    /// - visa:<ID>:blob
    pub async fn store_visa(&self, requesting_node: &IpAddr, visa: &Visa) -> Result<(), DBError> {
        // write capnpn version of visa into the store.
        let mut vk_conn = self.db.conn.clone();
        let visa_id = visa.issuer_id;

        let expiration_seconds = seconds_until(visa.expires);
        if expiration_seconds == 0 {
            return Err(DBError::InvalidData(
                "attempt to store already expired visa".into(),
            ));
        }

        // Store the whole visa in there in capnp format
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut visa_bldr = msg.init_root::<vsapi::visa::Builder>();
            visa.write_to(&mut visa_bldr);
            // Ends up dropping the visa_bldr and forgetting the mut borrow of msg.
        }

        let mut words: Vec<u8> = Vec::new();
        capnp::serialize::write_message(&mut words, &msg)?;

        let _: () = vk_conn
            .set_ex(
                format!("{KEY_VISA}:{visa_id}:blob"),
                &words,
                expiration_seconds,
            )
            .await?;

        let key_visa = format!("{KEY_VISAS}:{visa_id}");

        // Store metadata about visa too.
        // This is placeholder.  We may want five tuple here too.
        let _: () = vk_conn
            .hset_multiple(
                &key_visa,
                &[
                    ("requesting_node", requesting_node.to_string().as_str()),
                    ("ctime", &gen_timestamp()),
                ],
            )
            .await?;

        let _: () = vk_conn.expire(&key_visa, expiration_seconds as i64).await?;

        debug!(target: REDIS, "stored visa {visa_id} expires in {expiration_seconds} seconds");
        Ok(())
    }
}

// Get number of seconds until the given SystemTime or zero if in the past.

// Get number of seconds until the given SystemTime or zero if in the past.
fn seconds_until(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO)
        .as_secs()
}
