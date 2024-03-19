use thiserror::Error;

/// Describes things that can go wrong in registry handling
#[derive(Debug, Error)]
pub enum ModohRegistryError {}
