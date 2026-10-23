use super::types::*;

pub(super) fn import_issue_from_thunk(kind: ImportIssueKind, module: &ImportModule, thunk: &ImportThunk) -> ImportIssue {
    let (name, ordinal, address) = match &thunk.target {
        ImportTarget::Name { ordinal, name, .. } => (Some(name.clone()), *ordinal, None),
        ImportTarget::Ordinal(ordinal) => (None, Some(*ordinal), None),
        ImportTarget::Unknown(address) => (None, None, Some(*address)),
    };

    ImportIssue {
        kind,
        severity: kind.severity(),
        rva: thunk.rva,
        module_name: module.name.clone(),
        name,
        ordinal,
        address,
        next_rva: None,
        next_module_name: None,
    }
}

pub(super) fn import_issue_from_thunk_pair(
    kind: ImportIssueKind,
    module: &ImportModule,
    thunk: &ImportThunk,
    related_thunk: &ImportThunk,
) -> ImportIssue {
    let mut issue = import_issue_from_thunk(kind, module, thunk);

    issue.next_rva = Some(related_thunk.rva);
    issue.next_module_name = Some(module.name.clone());
    issue
}

pub(super) fn import_issue_from_import_entry_pair(
    kind: ImportIssueKind,
    entry: &ImportEntry,
    related_entry: &ImportEntry,
) -> ImportIssue {
    ImportIssue {
        kind,
        severity: kind.severity(),
        rva: entry.rva,
        module_name: entry.module_name.clone(),
        name: entry.name.clone(),
        ordinal: entry.ordinal,
        address: entry.address,
        next_rva: Some(related_entry.rva),
        next_module_name: Some(related_entry.module_name.clone()),
    }
}

pub(super) fn import_issue_from_thunk_and_gap(
    kind: ImportIssueKind,
    module: &ImportModule,
    thunk: &ImportThunk,
    gap_rva: u32,
) -> ImportIssue {
    let mut issue = import_issue_from_thunk(kind, module, thunk);

    issue.next_rva = Some(gap_rva);
    issue.next_module_name = Some(module.name.clone());
    issue
}

pub(super) fn import_issue_from_missing_thunk_run(
    kind: ImportIssueKind,
    module: &ImportModule,
    rva: u32,
    next_rva: Option<u32>,
) -> ImportIssue {
    ImportIssue {
        kind,
        severity: kind.severity(),
        rva,
        module_name: module.name.clone(),
        name: None,
        ordinal: None,
        address: None,
        next_rva,
        next_module_name: next_rva.map(|_| module.name.clone()),
    }
}

pub(super) fn import_issue_from_module_range(
    kind: ImportIssueKind,
    module: &ImportModule,
    rva: u32,
    next_rva: Option<u32>,
    next_module: Option<&ImportModule>,
) -> ImportIssue {
    ImportIssue {
        kind,
        severity: kind.severity(),
        rva,
        module_name: module.name.clone(),
        name: None,
        ordinal: None,
        address: None,
        next_rva,
        next_module_name: next_module.map(|module| module.name.clone()),
    }
}

pub(super) fn import_issue_from_repeated_import_target_run(
    module: &ImportModule,
    run: RepeatedImportTargetRun,
) -> Option<ImportIssue> {
    let thunk = module.thunks.get(&run.first_rva)?;
    let mut issue = import_issue_from_thunk(ImportIssueKind::RepeatedImportTargetRun, module, thunk);

    issue.next_rva = Some(run.last_rva);
    issue.next_module_name = Some(module.name.clone());
    Some(issue)
}

pub(super) fn import_module_range_end(module: &ImportModule, pointer_size: u32) -> Result<Option<u32>, ImportError> {
    if module.nb_thunks == 0 {
        return Ok(None);
    }

    let range_size = module
        .nb_thunks
        .checked_mul(pointer_size)
        .ok_or(ImportError::Overflow("sizing import module range"))?;
    module
        .first_thunk
        .checked_add(range_size)
        .map(Some)
        .ok_or(ImportError::Overflow("computing import module range"))
}

pub(super) fn sort_import_issues(issues: &mut [ImportIssue]) {
    issues.sort_by(|left, right| {
        left.severity
            .cmp(&right.severity)
            .then_with(|| left.rva.cmp(&right.rva))
            .then_with(|| left.kind.as_str().cmp(right.kind.as_str()))
            .then_with(|| left.module_name.cmp(&right.module_name))
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.ordinal.cmp(&right.ordinal))
            .then_with(|| left.address.cmp(&right.address))
            .then_with(|| left.next_rva.cmp(&right.next_rva))
            .then_with(|| left.next_module_name.cmp(&right.next_module_name))
    });
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RepeatedImportTargetRun {
    first_rva: u32,
    last_rva: u32,
}

pub(super) fn repeated_import_target_runs(
    module: &ImportModule,
    pointer_size: u32,
) -> Vec<RepeatedImportTargetRun> {
    let mut runs = Vec::new();
    let mut current_key = None;
    let mut current_first_rva = 0u32;
    let mut current_last_rva = 0u32;
    let mut current_count = 0usize;

    for thunk in module.thunks.values().filter(|thunk| thunk.valid) {
        let key = import_target_key(&thunk.target);
        let contiguous = current_last_rva
            .checked_add(pointer_size)
            .is_some_and(|next_rva| next_rva == thunk.rva);
        let extends_current = current_key.as_ref().is_some_and(|current_key| *current_key == key) && contiguous;

        if extends_current {
            current_last_rva = thunk.rva;
            current_count += 1;
            continue;
        }

        push_repeated_import_target_run(&mut runs, current_first_rva, current_last_rva, current_count);
        current_key = Some(key);
        current_first_rva = thunk.rva;
        current_last_rva = thunk.rva;
        current_count = 1;
    }

    push_repeated_import_target_run(&mut runs, current_first_rva, current_last_rva, current_count);
    runs
}

pub(super) fn push_repeated_import_target_run(
    runs: &mut Vec<RepeatedImportTargetRun>,
    first_rva: u32,
    last_rva: u32,
    count: usize,
) {
    if count >= 3 {
        runs.push(RepeatedImportTargetRun {
            first_rva,
            last_rva,
        });
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MissingThunkRun {
    pub(super) first_missing_rva: u32,
    pub(super) last_missing_rva: u32,
    pub(super) previous_thunk_rva: Option<u32>,
    pub(super) next_thunk_rva: Option<u32>,
}

pub(super) fn missing_thunk_runs(
    module: &ImportModule,
    pointer_size: u32,
) -> Result<Vec<MissingThunkRun>, ImportError> {
    let mut runs = Vec::new();
    let mut run_start = None;
    let mut run_last = None;
    let mut previous_thunk_rva = None;

    for index in 0..module.nb_thunks {
        let slot_offset = index
            .checked_mul(pointer_size)
            .ok_or(ImportError::Overflow("computing import module slot offset"))?;
        let slot_rva = module
            .first_thunk
            .checked_add(slot_offset)
            .ok_or(ImportError::Overflow("computing import module slot RVA"))?;

        if module.thunks.contains_key(&slot_rva) {
            if let (Some(first_missing_rva), Some(last_missing_rva)) = (run_start.take(), run_last.take()) {
                runs.push(MissingThunkRun {
                    first_missing_rva,
                    last_missing_rva,
                    previous_thunk_rva,
                    next_thunk_rva: Some(slot_rva),
                });
            }
            previous_thunk_rva = Some(slot_rva);
        } else {
            if run_start.is_none() {
                run_start = Some(slot_rva);
            }
            run_last = Some(slot_rva);
        }
    }

    if let (Some(first_missing_rva), Some(last_missing_rva)) = (run_start, run_last) {
        runs.push(MissingThunkRun {
            first_missing_rva,
            last_missing_rva,
            previous_thunk_rva,
            next_thunk_rva: None,
        });
    }

    Ok(runs)
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum ImportTargetKey {
    Name {
        name: String,
        ordinal: Option<u16>,
    },
    Ordinal(u16),
    Unknown(u64),
}

pub(super) fn import_target_key(target: &ImportTarget) -> ImportTargetKey {
    match target {
        ImportTarget::Name { ordinal, name, .. } => ImportTargetKey::Name {
            name: name.clone(),
            ordinal: *ordinal,
        },
        ImportTarget::Ordinal(ordinal) => ImportTargetKey::Ordinal(*ordinal),
        ImportTarget::Unknown(address) => ImportTargetKey::Unknown(*address),
    }
}
