use soroban_sdk::{contracttype, symbol_short, Address, BytesN, Env, Map, String, Symbol};

const ATTESTATION: Symbol = symbol_short!("ATTEST");
const ATTESTATION_ISSUED: Symbol = symbol_short!("ATISSUE");
const ATTESTATION_REVOKED: Symbol = symbol_short!("ATREVOKE");
const TTL_EXTEND: u32 = 17_280;
const TTL_LIFETIME: u32 = 6_312_000;

#[contracttype]
#[derive(Clone)]
pub struct Attestation {
    pub id: BytesN<32>,
    pub subject: Address,
    pub issuer: Address,
    pub claims: Map<String, String>,
    pub issued_at_ledger: u32,
    pub expires_at_ledger: u32,
    pub revoked: bool,
}

fn storage_key(id: &BytesN<32>) -> (Symbol, BytesN<32>) {
    (ATTESTATION, id.clone())
}

pub fn store(env: &Env, attestation: &Attestation) {
    let key = storage_key(&attestation.id);
    env.storage().persistent().set(&key, attestation);
    env.storage()
        .persistent()
        .extend_ttl(&key, TTL_EXTEND, TTL_LIFETIME);
}

pub fn get(env: &Env, id: &BytesN<32>) -> Option<Attestation> {
    env.storage()
        .persistent()
        .get::<(Symbol, BytesN<32>), Attestation>(&storage_key(id))
}

pub fn is_expired(env: &Env, attestation: &Attestation) -> bool {
    attestation.expires_at_ledger != 0
        && env.ledger().sequence() > attestation.expires_at_ledger
}

pub fn verify_attestation(env: &Env, id: &BytesN<32>) -> bool {
    match get(env, id) {
        None => false,
        Some(attestation) => {
            if attestation.revoked || is_expired(env, &attestation) {
                return false;
            }
            env.storage()
                .persistent()
                .extend_ttl(&storage_key(id), TTL_EXTEND, TTL_LIFETIME);
            true
        }
    }
}

pub fn revoke_attestation(env: &Env, issuer: &Address, id: &BytesN<32>) -> bool {
    let mut attestation = match get(env, id) {
        Some(value) => value,
        None => return false,
    };
    if attestation.issuer != issuer.clone() {
        return false;
    }
    attestation.revoked = true;
    store(env, &attestation);
    env.events()
        .publish((ATTESTATION, ATTESTATION_REVOKED), id.clone());
    true
}

pub fn issue_attestation(
    env: &Env,
    issuer: &Address,
    id: BytesN<32>,
    subject: Address,
    claims: Map<String, String>,
    expires_at_ledger: u32,
) -> bool {
    if get(env, &id).is_some() {
        return false;
    }
    let attestation = Attestation {
        id: id.clone(),
        subject,
        issuer: issuer.clone(),
        claims,
        issued_at_ledger: env.ledger().sequence(),
        expires_at_ledger,
        revoked: false,
    };
    store(env, &attestation);
    env.events()
        .publish((ATTESTATION, ATTESTATION_ISSUED), id);
    true
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger as _};

    fn setup() -> (Env, Address, Address, BytesN<32>) {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().with_mut(|li| li.sequence_number = 100);
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);
        let id = BytesN::<32>::from_array(&env, &[7u8; 32]);
        (env, issuer, subject, id)
    }

    fn claims(env: &Env) -> Map<String, String> {
        let mut claims = Map::new(env);
        claims.set(String::from_str(env, "role"), String::from_str(env, "verified"));
        claims
    }

    #[test]
    fn verify_fails_when_attestation_is_missing() {
        let (env, _issuer, _subject, id) = setup();
        assert!(!verify_attestation(&env, &id));
    }

    #[test]
    fn verify_succeeds_before_the_expiry_ledger() {
        let (env, issuer, subject, id) = setup();
        assert!(issue_attestation(&env, &issuer, id.clone(), subject, claims(&env), 150));
        assert!(verify_attestation(&env, &id));
    }

    #[test]
    fn verify_fails_once_the_expiry_ledger_is_passed() {
        let (env, issuer, subject, id) = setup();
        assert!(issue_attestation(&env, &issuer, id.clone(), subject, claims(&env), 150));
        env.ledger().with_mut(|li| li.sequence_number = 151);
        assert!(!verify_attestation(&env, &id));
    }

    #[test]
    fn expiry_is_enforced_by_expiry_ledger_not_timestamp() {
        let (env, issuer, subject, id) = setup();
        assert!(issue_attestation(&env, &issuer, id.clone(), subject, claims(&env), 150));
        env.ledger().with_mut(|li| {
            li.sequence_number = 151;
            li.timestamp = 10;
        });
        assert!(is_expired(&env, &get(&env, &id).unwrap()));
        assert!(!verify_attestation(&env, &id));
    }

    #[test]
    fn zero_expiry_means_no_expiry() {
        let (env, issuer, subject, id) = setup();
        assert!(issue_attestation(&env, &issuer, id.clone(), subject, claims(&env), 0));
        env.ledger().with_mut(|li| li.sequence_number = 10_000);
        assert!(verify_attestation(&env, &id));
    }

    #[test]
    fn revoked_attestation_fails_verification() {
        let (env, issuer, subject, id) = setup();
        assert!(issue_attestation(&env, &issuer, id.clone(), subject, claims(&env), 150));
        assert!(revoke_attestation(&env, &issuer, &id));
        assert!(!verify_attestation(&env, &id));
    }

    #[test]
    fn only_the_issuer_can_revoke_an_attestation() {
        let (env, issuer, subject, id) = setup();
        assert!(issue_attestation(&env, &issuer, id.clone(), subject, claims(&env), 150));
        let other = Address::generate(&env);
        assert!(!revoke_attestation(&env, &other, &id));
        assert!(verify_attestation(&env, &id));
    }

    #[test]
    fn duplicate_attestation_ids_are_rejected() {
        let (env, issuer, subject, id) = setup();
        assert!(issue_attestation(&env, &issuer, id.clone(), subject.clone(), claims(&env), 150));
        assert!(!issue_attestation(&env, &issuer, id, subject, claims(&env), 150));
    }
}
