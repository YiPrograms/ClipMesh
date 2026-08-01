pub use clipmesh_protocol::crypto::{JOIN_LABEL, item_key, join_message, sha256};

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serde::Deserialize;
    use uuid::Uuid;

    #[derive(Deserialize)]
    struct Vectors {
        channel_root_key_hex: String,
        channel_id: Uuid,
        item_id: Uuid,
        server_instance_id: Uuid,
        device_id: Uuid,
        challenge_id: Uuid,
        challenge_random_base64: String,
        expires_at: i64,
        item_key_hex: String,
        join_message_hex: String,
    }

    fn vectors() -> Vectors {
        serde_json::from_str(include_str!("../../protocol/test-vectors.json")).unwrap()
    }

    #[test]
    fn join_message_is_unambiguous_and_stable() {
        let ids = [
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            Uuid::from_u128(4),
        ];
        let message = join_message(ids[0], ids[1], ids[2], ids[3], &[5; 32], 6);
        assert_eq!(message.len(), JOIN_LABEL.len() + 104);
        assert_eq!(&message[..JOIN_LABEL.len()], JOIN_LABEL);
        assert_eq!(&message[message.len() - 8..], &6_i64.to_be_bytes());
    }

    #[test]
    fn matches_shared_typescript_vectors() {
        let vector = vectors();
        let root: [u8; 32] = hex::decode(vector.channel_root_key_hex)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            hex::encode(item_key(&root, vector.channel_id, vector.item_id)),
            vector.item_key_hex
        );
        let random: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(vector.challenge_random_base64)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            hex::encode(join_message(
                vector.server_instance_id,
                vector.channel_id,
                vector.device_id,
                vector.challenge_id,
                &random,
                vector.expires_at,
            )),
            vector.join_message_hex
        );
    }
}
