use super::HttpSigKeyRotationState;
use crate::{globals::HttpSigDomainInfo, trace::*};
use cedarwood::Cedar;
use httpsig::prelude::{PublicKey as RawPublicKey, SecretKey as RawSecretKey, SigningKey, VerifyingKey};
use httpsig_proto::{DeriveKeyId, HmacSha256HkdfSha256, HttpSigConfigContents, HttpSigKeyPair, KemKdfDerivedSecret};
use indexmap::IndexMap;
use regex::Regex;
use rustc_hash::FxHashMap as HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

type KeyId = String;
type DomainName = String;
type Generation = usize;
type GenerationToKeyIdsMap = IndexMap<Generation, Vec<KeyId>>;

/* ------------------------------------------------ */
#[derive(Debug, Clone)]
/// Public key for verification or DH master key for signing and verification
pub(crate) enum TypedKey {
  Pk(PublicKey),
  Dh(DerivedSecret),
}

#[allow(unused)]
impl TypedKey {
  /// Get generation
  pub(super) fn generation(&self) -> usize {
    match self {
      TypedKey::Pk(pk) => pk.generation,
      TypedKey::Dh(dh) => dh.generation,
    }
  }
}

/* ------------------------------------------------ */

/// Http message signature key management state
pub(crate) struct HttpSigKeyMapState {
  /// key id to verification key maps, which includes public key and dh master key.
  /// key_ids for DH keys included in this map are ones of keys generated with the latest and previous self states
  pub(crate) key_id_maps: RwLock<KeyIdToVerificationKeyMap>,
  /// domain to key id map using trie in order to select appropriate hmac master key to destination domain
  /// key_ids included in this map are ones of keys generated with each generation of self state,
  /// where the first one is the latest self state
  pub(crate) domain_maps: RwLock<TargetDomainToKeyIdMap>,
  /// my secret keys for public key based signature
  pub(crate) owned_pk_type_key_pairs: RwLock<OwnedPkTypeKeyPairs>,
  /// configurations fetched from specified nodes
  config_with_info: RwLock<Vec<(Vec<HttpSigConfigContents>, HttpSigDomainInfo)>>,
}

impl HttpSigKeyMapState {
  /// Create a new state
  pub(crate) fn new() -> Self {
    Self {
      key_id_maps: RwLock::new(KeyIdToVerificationKeyMap::new()),
      domain_maps: RwLock::new(TargetDomainToKeyIdMap::new()),
      owned_pk_type_key_pairs: RwLock::new(OwnedPkTypeKeyPairs::new()),
      config_with_info: RwLock::new(Vec::new()),
    }
  }

  /// Update state, this clears existing key_id_maps and recreate it.
  pub(crate) async fn update_with_new_self_state(&self, self_state: &Arc<HttpSigKeyRotationState>) {
    debug!("Update HttpSigKeyMapState with self state");
    let mut key_id_map = KeyIdToVerificationKeyMap::new();
    let mut domain_map: TargetDomainToKeyIdMap = TargetDomainToKeyIdMap::new();
    let mut owned_pk_type_key_pairs = OwnedPkTypeKeyPairs::new();

    let lock = self.config_with_info.read().await;
    let config_with_info = lock.clone();
    drop(lock);
    let config_with_info = config_with_info.iter().map(|(c, i)| (c, i)).collect::<Vec<_>>();

    // verification key for standard public key based signature. easy to handle
    derive_and_set_pk(&mut key_id_map, &config_with_info);

    // dhkex public key for hmac signature. need to handle with care
    // update domain to key id map too
    derive_and_set_dh(&mut key_id_map, &mut domain_map, self_state, &config_with_info).await;

    // secret key for public key based signature
    owned_pk_type_key_pairs.set_key_pairs(self_state).await;

    let mut lock = self.key_id_maps.write().await;
    *lock = key_id_map;
    drop(lock);

    let mut lock = self.domain_maps.write().await;
    *lock = domain_map;
    drop(lock);

    let mut lock = self.owned_pk_type_key_pairs.write().await;
    *lock = owned_pk_type_key_pairs;
    drop(lock);
  }

  /// Update state with fetched external configs, this clears existing key_id_maps and recreate it.
  pub(crate) async fn update_with_new_external_configs(
    &self,
    self_state: &Arc<HttpSigKeyRotationState>,
    config_with_info: &[(&Vec<HttpSigConfigContents>, &HttpSigDomainInfo)],
  ) {
    debug!("Update HttpSigKeyMapState with new fetched configurations and self_state");
    let mut lock = self.config_with_info.write().await;
    *lock = config_with_info
      .iter()
      .map(|(c, i)| (c.to_vec(), i.to_owned().to_owned()))
      .collect::<Vec<_>>();
    drop(lock);

    self.update_with_new_self_state(self_state).await;
  }

  /// Get key_ids for the domain for the generation of key rotation.
  /// If empty, it means no key to generate the hmac signature for the domain.
  /// Then try to generate the public key based signature by checking.
  pub(crate) async fn get_key_ids(&self, domain: &str) -> GenerationToKeyIdsMap {
    self.domain_maps.read().await.get_key_ids(domain)
  }
  /// Key typed key for the key_id if exists
  pub(crate) async fn get_typed_key(&self, key_id: &str) -> Option<TypedKey> {
    let key_type = self.get_key_type(key_id).await?;
    match key_type {
      KeyType::Pk(_) => self.get_pk(key_id).await.map(TypedKey::Pk),
      KeyType::Dh(_) => self.get_dh(key_id).await.map(TypedKey::Dh),
    }
  }
  /// Get public key type signing key
  pub(crate) async fn get_pk_type_key_pairs(&self) -> Vec<RawSecretKey> {
    self.owned_pk_type_key_pairs.read().await.secret_keys.to_owned()
  }

  /// Get key type for the key_id if exists
  async fn get_key_type(&self, key_id: &str) -> Option<KeyType> {
    self.key_id_maps.read().await.type_map.get(key_id).cloned()
  }
  /// Get public key for the key_id if exists
  async fn get_pk(&self, key_id: &str) -> Option<PublicKey> {
    self.key_id_maps.read().await.pk_inner.get(key_id).cloned()
  }
  /// Get dh master key for the key_id if exists
  async fn get_dh(&self, key_id: &str) -> Option<DerivedSecret> {
    self.key_id_maps.read().await.dh_inner.get(key_id).cloned()
  }
}

/* ------------------------------------------------ */
/// Derive key_ids from key pair for dhkex based signature and set them to the map
async fn derive_and_set_dh(
  key_id_map: &mut KeyIdToVerificationKeyMap,
  domain_map: &mut TargetDomainToKeyIdMap,
  self_state: &Arc<HttpSigKeyRotationState>,
  config_with_info: &[(&Vec<HttpSigConfigContents>, &HttpSigDomainInfo)],
) {
  let mut my_key_pairs = Vec::new();
  // current config
  let lock = self_state.configs.read().await;
  my_key_pairs.push(lock.clone());
  drop(lock);

  // previous configs
  let lock = self_state.previous_configs.read().await;
  my_key_pairs.extend(lock.iter().cloned());
  drop(lock);

  let my_dh_key_pairs_for_generation = my_key_pairs
    .iter()
    .map(|v| {
      // generation 0 is the current config
      v.as_key_pairs()
        .iter()
        .filter_map(move |v| match v {
          HttpSigKeyPair::Dh(c) => Some(c.to_owned()),
          _ => None,
        })
        .collect::<Vec<_>>()
    })
    .collect::<Vec<_>>();

  let other_dh_key_pairs = config_with_info
    .iter()
    .flat_map(|(configs, info)| configs.iter().map(|c| (c, info.dh_signing_target_domain.to_owned())))
    .filter_map(|(c, target_domain)| match c {
      HttpSigConfigContents::Dh(c) => Some((c.to_owned(), target_domain)),
      _ => None,
    })
    .collect::<Vec<_>>();

  let dhkex_res_for_generation = my_dh_key_pairs_for_generation
    .iter()
    .enumerate()
    .map(|(generation, mine)| {
      // calculate dhkex at a specific generation
      let maps = mine
        .iter()
        .flat_map(|my_key_pair| {
          other_dh_key_pairs
            .iter()
            .map(move |(other, target_domain)| (my_key_pair, other, target_domain))
        })
        .collect::<Vec<_>>();

      maps
        .iter()
        .filter_map(|(my_key_pair, other, target_domain)| {
          if my_key_pair.is_same_kem_kdf_mac(other) {
            my_key_pair.derive_secret(other).ok().map(|derived| {
              let key_id = derived.key_id();
              info!("DHKex for HTTPSig: {target_domain} id = {key_id} (generation {generation})",);
              (derived, key_id, target_domain.to_owned(), generation)
            })
          } else {
            None
          }
        })
        .collect::<Vec<_>>()
    })
    .collect::<Vec<_>>();

  // update key_id_map and domain_map
  // key id map includes all the keys generated with the latest and previous self states
  let key_id_to_dhkex_master = dhkex_res_for_generation
    .iter()
    .flatten()
    .map(|(derived, key_id, _, gen)| (key_id.to_owned(), derived.to_owned(), gen.to_owned()));
  key_id_map.set_dh_inner(key_id_to_dhkex_master);
  // domain map includes only the keys generated with with self state for each generation
  let master_id_to_domain_for_gen = dhkex_res_for_generation
    .iter()
    .map(|v| {
      v.iter()
        .map(|(_derived, key_id, domain, _gen)| (key_id.to_owned(), domain.to_owned().to_owned()))
        .collect::<Vec<_>>()
    })
    .collect::<Vec<_>>();
  domain_map.set_trie(master_id_to_domain_for_gen.iter());
}

/// Derive key_ids from key pair for pk based signature and set them to the map
fn derive_and_set_pk(
  key_id_map: &mut KeyIdToVerificationKeyMap,
  config_with_info: &[(&Vec<HttpSigConfigContents>, &HttpSigDomainInfo)],
) {
  let vk_for_pubkey_signature = config_with_info
    .iter()
    .flat_map(|(config, _)| config.to_owned())
    .filter_map(|v| match v {
      HttpSigConfigContents::Pk(c) => Some(c),
      _ => None,
    })
    .filter_map(|c| c.try_export().ok()) // omit parse failure
    .map(|c| {
      debug!(
        "Available public key for public key based httpsig verification: id = {}",
        c.key_id()
      );
      (c.key_id(), c)
    });
  key_id_map.set_pk_inner(vk_for_pubkey_signature);
}
/* ------------------------------------------------ */
#[derive(Debug, Clone)]
/// Owned key pairs for public key type signature
pub(super) struct OwnedPkTypeKeyPairs {
  pub(super) secret_keys: Vec<RawSecretKey>,
}
impl OwnedPkTypeKeyPairs {
  /// Create a new key pair
  pub(super) fn new() -> Self {
    Self { secret_keys: Vec::new() }
  }
  /// Set key pairs
  pub(super) async fn set_key_pairs(&mut self, self_state: &Arc<HttpSigKeyRotationState>) {
    let lock = self_state.configs.read().await;
    let secret_keys = lock
      .as_key_pairs()
      .iter()
      .filter_map(|v| match v {
        HttpSigKeyPair::Pk(c) => Some(c.to_owned()),
        _ => None,
      })
      .filter_map(|c| c.try_export_sk().ok())
      .collect::<Vec<_>>();
    drop(lock);
    debug!(
      "Available secret keys for public key based httpsig signing: ids = {:?}",
      secret_keys.iter().map(SigningKey::key_id).collect::<Vec<_>>()
    );
    self.secret_keys = secret_keys;
  }
}

/* ------------------------------------------------ */
#[allow(unused)]
#[derive(Debug, Clone)]
/// Key type with generation, where if generation == 0, it means the latest key
enum KeyType {
  Pk(Generation),
  Dh(Generation),
}
#[derive(Debug, Clone)]
/// Public key with generation, where if generation == 0, it means the latest key
pub(super) struct PublicKey {
  pub(super) inner: RawPublicKey,
  pub(super) generation: usize,
}
#[derive(Debug, Clone)]
/// Kem-Kdf Shared secret with generation, where if generation == 0, it means the latest secret
pub(super) struct DerivedSecret {
  pub(super) inner: KemKdfDerivedSecret<HmacSha256HkdfSha256>,
  pub(super) generation: usize,
}

/// Fetched key's key_id-to-verification_key map
pub(super) struct KeyIdToVerificationKeyMap {
  /// Key type map
  type_map: HashMap<KeyId, KeyType>,
  /// Public key map
  pk_inner: HashMap<KeyId, PublicKey>,
  /// DH key map
  dh_inner: HashMap<KeyId, DerivedSecret>,
}

impl KeyIdToVerificationKeyMap {
  /// Create a new map
  pub(super) fn new() -> Self {
    Self {
      type_map: HashMap::default(),
      pk_inner: HashMap::default(),
      dh_inner: HashMap::default(),
    }
  }
  /// Set pk_inner, this clears existing pk_inner and recreate type_map.
  pub(super) fn set_pk_inner(&mut self, pk_inner: impl Iterator<Item = (KeyId, RawPublicKey)>) {
    self.pk_inner = pk_inner
      .map(|(key_id, pk)| {
        (
          key_id,
          PublicKey {
            inner: pk,
            generation: 0usize,
          },
        )
      })
      .collect();
    self.refresh_type_map();
  }
  /// Set dh_inner, this clears existing dh_inner and recreate type_map.
  pub(super) fn set_dh_inner(
    &mut self,
    dh_inner: impl Iterator<Item = (KeyId, KemKdfDerivedSecret<HmacSha256HkdfSha256>, Generation)>,
  ) {
    self.dh_inner = dh_inner
      .map(|(key_id, secret, generation)| {
        (
          key_id,
          DerivedSecret {
            inner: secret,
            generation,
          },
        )
      })
      .collect();
    self.refresh_type_map();
  }
  /// refresh type_map
  fn refresh_type_map(&mut self) {
    self.type_map.clear();
    self.type_map.extend(
      self
        .pk_inner
        .iter()
        .map(|(key_id, pk)| (key_id.to_owned(), KeyType::Pk(pk.generation))),
    );
    self.type_map.extend(
      self
        .dh_inner
        .iter()
        .map(|(key_id, secret)| (key_id.to_owned(), KeyType::Dh(secret.generation))),
    );
  }
}

/* ------------------------------------------------ */
/// Fetched key's domain-to-key_id map for DH-based key using cerdarwood,
/// which is used to check if the next node supports DH-based Kex for signature verification,
/// and retrieve hamc key if supported.
pub(super) struct TargetDomainToKeyIdMap {
  suffix_idx_cedar: Cedar,
  idx_suffix_map: IndexMap<usize, String>,
  idx_key_ids_map: IndexMap<usize, GenerationToKeyIdsMap>,
}

/// Regex for domain or prefix matching
const REGEXP_DOMAIN_OR_PREFIX: &str = r"^([a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.)+([a-zA-Z]{2,}|\*)";

impl TargetDomainToKeyIdMap {
  /// build new empty map
  pub(super) fn new() -> Self {
    Self {
      suffix_idx_cedar: Cedar::new(),
      idx_suffix_map: IndexMap::new(),
      idx_key_ids_map: IndexMap::new(),
    }
  }
  /// Update map, this clears existing suffix_idx_cedar and idx_key_ids_map and recreate them.
  pub(super) fn set_trie<'a>(&mut self, master_id_domain: impl Iterator<Item = &'a Vec<(KeyId, DomainName)>>) {
    let start_with_star = Regex::new(r"^\*\..+").unwrap();
    let re = Regex::new(&format!("{}{}{}", r"^", REGEXP_DOMAIN_OR_PREFIX, r"$")).unwrap();
    let mut hashmap: HashMap<DomainName, GenerationToKeyIdsMap> = HashMap::default();
    for (generation, key_id, domain) in master_id_domain
      .enumerate()
      .flat_map(|(generation, v)| v.iter().map(move |(k, v)| (generation, k, v)))
    {
      let domain = if start_with_star.is_match(domain) {
        &domain[2..]
      } else {
        domain
      };
      let domain = domain.to_ascii_lowercase();
      if re.is_match(&domain) || (domain.split('.').count() == 1) {
        hashmap
          .entry(domain)
          .or_default()
          .entry(generation)
          .or_default()
          .push(key_id.to_owned());
      }
    }
    let suffix_dict_with_index = hashmap
      .iter()
      .map(|(domain, key_ids_for_generation)| {
        let domain = if start_with_star.is_match(domain) {
          &domain[2..]
        } else {
          domain
        };
        let domain = domain.to_ascii_lowercase();
        (domain, key_ids_for_generation.to_owned())
      })
      .filter(|(domain, _)| re.is_match(domain) || (domain.split('.').count() == 1))
      .map(|(domain, key_ids)| (reverse_string(&domain), key_ids))
      .enumerate()
      .collect::<Vec<_>>();

    // build mapper from suffix matching to index
    let suffix_idx_kv = suffix_dict_with_index
      .iter()
      .map(|(idx, (domain, _))| (domain.as_ref(), idx.to_owned() as i32))
      .collect::<Vec<_>>();
    let mut suffix_idx_cedar = Cedar::new();
    suffix_idx_cedar.build(&suffix_idx_kv);
    let suffix_idx_map = suffix_dict_with_index
      .iter()
      .map(|(idx, (domain, _))| (idx.to_owned(), domain.to_owned()))
      .collect::<IndexMap<_, _>>();

    // build mapper from index to key_ids
    let idx_key_ids_map = suffix_dict_with_index
      .iter()
      .map(|(idx, (_, key_ids_for_generation))| (idx.to_owned(), key_ids_for_generation.to_owned()))
      .collect::<IndexMap<_, _>>();

    self.suffix_idx_cedar = suffix_idx_cedar;
    self.idx_suffix_map = suffix_idx_map;
    self.idx_key_ids_map = idx_key_ids_map;
  }

  /// Get key_ids for the domain for the generation of key rotation.
  pub(super) fn get_key_ids(&self, domain: &str) -> GenerationToKeyIdsMap {
    let rev_nn = reverse_string(domain);
    let matched_items = self.suffix_idx_cedar.common_prefix_iter(&rev_nn).filter_map(|(x, _)| {
      let target_domain = self.idx_suffix_map.get(&(x as usize)).map(|v| v.to_owned());
      let available_key_ids = self.idx_key_ids_map.get(&(x as usize)).map(|v| v.to_owned());
      target_domain.zip(available_key_ids)
    });

    let found_ids_for_generation = matched_items
      .filter(|(found_domain, _)| {
        if found_domain.len() == rev_nn.len() {
          true
        } else if let Some(nth) = rev_nn.chars().nth(found_domain.chars().count()) {
          nth.to_string() == "."
        } else {
          false
        }
      })
      .flat_map(|(_, key_ids)| key_ids);
    let mut res = IndexMap::new();
    found_ids_for_generation.for_each(|(generation, key_ids)| {
      res.entry(generation).or_insert(Vec::new()).extend(key_ids);
    });
    res
  }
}

/// Support function for reverse string
fn reverse_string(text: &str) -> String {
  text.chars().rev().collect::<String>()
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn test_target_domain_key_ids_map() {
    let key_ids_map_current = [vec![
      ("test_key_id_10".to_string(), "test.example.com".to_string()),
      ("test_key_id_11".to_string(), "test.example.com".to_string()),
      ("test_key_id_20".to_string(), "test.example.org".to_string()),
      ("test_key_id_30".to_string(), "*.example.org".to_string()),
    ]];

    let mut target_domain_key_ids_map = TargetDomainToKeyIdMap::new();
    target_domain_key_ids_map.set_trie(key_ids_map_current.iter());

    // testing
    let target_domain = "test.example.com";
    let matched_indices = target_domain_key_ids_map.get_key_ids(target_domain);
    assert!(
      matched_indices.get(&0).unwrap().contains(&"test_key_id_10".to_string())
        && matched_indices.get(&0).unwrap().contains(&"test_key_id_11".to_string())
    );

    let target_domain = "test.example.org";
    let matched_indices = target_domain_key_ids_map.get_key_ids(target_domain);
    assert!(
      matched_indices.get(&0).unwrap().contains(&"test_key_id_20".to_string())
        && matched_indices.get(&0).unwrap().contains(&"test_key_id_30".to_string())
    );

    let target_domain = "testtest.example.org";
    let matched_indices = target_domain_key_ids_map
      .get_key_ids(target_domain)
      .iter()
      .flat_map(|(_, v)| v.clone())
      .collect::<Vec<_>>();
    assert_eq!(matched_indices, vec!["test_key_id_30"]);

    let target_domain = "not_matched.example.com";
    let matched_indices = target_domain_key_ids_map.get_key_ids(target_domain);
    assert!(matched_indices.is_empty());
  }
}
