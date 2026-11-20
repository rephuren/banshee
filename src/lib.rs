//! banshee: a small Sigma and YARA engine. Rules and the data they run on are untrusted input: every loader returns
//! errors instead of panicking, and anything the engine does not understand is reported, never silently ignored.

pub mod attack;
pub mod sigma;
