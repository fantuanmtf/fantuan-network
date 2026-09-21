//! `fantuan-node identity` subcommands.

use anyhow::{Context, Result, bail};
use fantuan_core::{config::NodeConfig, fs as secure_fs, time};
use fantuan_identity::{Descriptor, Identity, PeerRecord, TrustGraph, TrustStore, TrustVouch};
use fantuan_transport::sam::{SamConfig, generate_destination};
use std::path::{Path, PathBuf};

/// File holding the persistent I2P destination private key.
pub const I2P_KEY_FILE: &str = "i2p.key";

/// Load the node identity, with an actionable error when it is missing.
pub fn load_identity(config: &NodeConfig) -> Result<Identity> {
    let dir = config.identity_dir();
    if !dir.join(fantuan_identity::keys::SECRET_FILE).exists() {
        bail!(
            "no identity in {}; run `fantuan-node identity init` first",
            dir.display()
        );
    }
    Identity::load(&dir).context("failed to load identity")
}

/// Load the persistent I2P private key.
pub fn i2p_private_key(config: &NodeConfig) -> Result<String> {
    let path = config.identity_dir().join(I2P_KEY_FILE);
    let bytes = secure_fs::read_file(&path)
        .with_context(|| format!("missing {}; run `identity init`", path.display()))?;
    String::from_utf8(bytes).context("i2p.key is not valid UTF-8")
}

/// Generate an OpenPGP identity and a persistent I2P destination.
pub async fn init(config: &NodeConfig, uid: Option<&str>, force: bool) -> Result<Identity> {
    let dir = config.identity_dir();
    if dir.join(fantuan_identity::keys::SECRET_FILE).exists() && !force {
        bail!(
            "identity already exists in {} (use --force to overwrite)",
            dir.display()
        );
    }

    let uid = uid.unwrap_or(&config.display_name);
    let port = SamConfig::from_addr(&config.sam_addr)?.port;
    let sam = SamConfig {
        port,
        nickname: format!("fantuan-init-{}", std::process::id()),
        publish: true,
    };

    println!("generating I2P destination (this can take a few seconds)...");
    let (destination, private_key) = generate_destination(&sam)
        .await
        .context("SAM destination generation failed")?;

    let identity = Identity::generate(uid, &destination)?;
    identity.save(&dir)?;
    secure_fs::write_private_file(&dir.join(I2P_KEY_FILE), private_key.as_bytes())?;
    Ok(identity)
}

/// Human-readable identity summary.
pub fn show(identity: &Identity) -> String {
    let descriptor = identity.descriptor();
    format!(
        "uid:          {}\nfingerprint:  {}\ni2p:          {}\nnoise key:    {}\ncapabilities: {}\ncreated:      {}\n",
        descriptor.uid,
        identity.fingerprint_hex(),
        descriptor.i2p_destination,
        hex::encode(identity.noise_public()),
        descriptor.capabilities.join(", "),
        descriptor.created,
    )
}

/// Copy the public identity material into `out_dir`.
pub fn export(config: &NodeConfig, out_dir: &Path) -> Result<Vec<PathBuf>> {
    let identity_dir = config.identity_dir();
    secure_fs::ensure_dir_0700(out_dir)?;

    let mut exported = Vec::new();
    for name in [
        fantuan_identity::keys::CERT_FILE,
        fantuan_identity::keys::DESCRIPTOR_FILE,
        fantuan_identity::keys::DESCRIPTOR_SIG_FILE,
    ] {
        let source = identity_dir.join(name);
        let target = out_dir.join(name);
        let bytes = secure_fs::read_file(&source)
            .with_context(|| format!("missing {}", source.display()))?;
        secure_fs::write_private_file(&target, &bytes)?;
        exported.push(target);
    }
    Ok(exported)
}

/// Verify an imported descriptor and record the peer in the trust store.
pub fn import(
    config: &NodeConfig,
    descriptor_path: &Path,
    signature_path: &Path,
) -> Result<Descriptor> {
    let descriptor_bytes = secure_fs::read_file(descriptor_path)
        .with_context(|| format!("cannot read {}", descriptor_path.display()))?;
    let signature = secure_fs::read_file(signature_path)
        .with_context(|| format!("cannot read {}", signature_path.display()))?;

    let descriptor = Descriptor::from_canonical(&descriptor_bytes)
        .context("descriptor is not valid canonical CBOR")?;
    descriptor
        .verify(&signature)
        .context("descriptor signature does not verify")?;

    let store = TrustStore::open(&config.trust_db_path())?;
    store.upsert_peer(
        &descriptor.fingerprint,
        &descriptor.uid,
        &hex::encode(&descriptor.openpgp_cert),
        time::now_unix(),
    )?;
    Ok(descriptor)
}

/// List peers recorded in the trust store.
pub fn list_peers(config: &NodeConfig) -> Result<Vec<PeerRecord>> {
    let store = TrustStore::open(&config.trust_db_path())?;
    Ok(store.peers(10_000)?)
}

/// Create a locally signed trust vouch for a peer (fingerprint or uid).
///
/// Returns the resolved peer fingerprint.
pub fn set_trust(config: &NodeConfig, target: &str, level: u8) -> Result<String> {
    let identity = load_identity(config)?;
    let store = TrustStore::open(&config.trust_db_path())?;
    let fingerprint = resolve_peer(&store, target)?;
    let now = time::now_unix();
    let vouch = TrustVouch::create(&identity, &fingerprint, level, now)?;
    store.set_relationship(
        &identity.fingerprint_hex(),
        &fingerprint,
        level,
        now,
        &vouch.signature,
    )?;

    let mut graph = TrustGraph::new(&store, identity.fingerprint_hex());
    graph.refresh_scores()?;
    Ok(fingerprint)
}

fn resolve_peer(store: &TrustStore, target: &str) -> Result<String> {
    if store.get_peer(target)?.is_some() {
        return Ok(target.to_string());
    }
    for peer in store.peers(10_000)? {
        if peer.uid == target {
            return Ok(peer.fingerprint);
        }
    }
    bail!("unknown peer {target:?}; import or discover its descriptor first")
}
