use super::*;
use super::editor::{Editor, ChangeKind};
use super::resources::{ResourceDataLeaf, rebase_resource_directory_data_rvas, build_resource_directory_data};
use crate::pe::{capture::Capture, diagnostics::comparison::Comparison};

mod fixtures;
use fixtures::*;

mod comparison;
mod editing;
mod headers;
mod layout;
mod recovery;
mod resources;
