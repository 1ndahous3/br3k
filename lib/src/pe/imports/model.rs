use super::*;
use super::issues::*;
use super::recover::*;
use super::resolver::*;
use super::types::*;
use super::util::*;

#[derive(Clone, Debug, Default)]
pub struct ImportModel {
    pub(super) modules: BTreeMap<String, ImportModule>,
}

impl ImportModel {
    pub fn add_module(
        &mut self,
        name: &str,
        first_thunk: u32,
        nb_thunks: u32,
    ) -> Result<(), ImportError> {
        validate_cstr(name)?;

        self.modules.insert(
            module_key(name),
            ImportModule {
                name: name.to_string(),
                first_thunk,
                nb_thunks,
                thunks: BTreeMap::new(),
            },
        );

        Ok(())
    }

    pub fn add_function(
        &mut self,
        module_name: &str,
        rva: u32,
        target: ImportTarget,
        valid: bool,
        force: bool,
    ) -> Result<(), ImportError> {
        self.add_function_with_evidence(
            module_name,
            rva,
            target,
            valid,
            force,
            Vec::new(),
        )
    }

    pub fn add_function_with_evidence(
        &mut self,
        module_name: &str,
        rva: u32,
        target: ImportTarget,
        valid: bool,
        force: bool,
        evidence: Vec<ImportEvidence>,
    ) -> Result<(), ImportError> {
        validate_import_target(&target)?;
        let evidence = if evidence.is_empty() {
            vec![ImportEvidence::manual_slot(rva, &target, valid)]
        } else {
            evidence
        };

        let module = self
            .modules
            .get_mut(&module_key(module_name))
            .ok_or_else(|| ImportError::ModuleNotFound(module_name.to_string()))?;

        if !force && module.thunks.contains_key(&rva) {
            return Err(ImportError::DuplicateThunk(module.name.clone(), rva));
        }

        module.thunks.insert(rva, ImportThunk { rva, target, valid, evidence });
        Ok(())
    }

    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    pub fn function_count(&self) -> usize {
        self.modules.values().map(|module| module.thunks.len()).sum()
    }

    pub fn set_function_validity(&mut self, rva: u32, valid: bool) -> Result<(), ImportError> {
        let thunk = self.function_mut(rva).ok_or(ImportError::FunctionNotFound(rva))?;
        thunk.valid = valid;
        Ok(())
    }

    pub fn remove_function(&mut self, rva: u32) -> Result<(), ImportError> {
        let key = self.module_key_by_thunk_rva(rva).ok_or(ImportError::FunctionNotFound(rva))?;
        let remove_module = match self.modules.get_mut(&key) {
            Some(module) => {
                module.thunks.remove(&rva);
                module.thunks.is_empty()
            }
            None => false,
        };

        if remove_module {
            self.modules.remove(&key);
        }

        Ok(())
    }

    pub fn remove_module_containing_thunk(&mut self, rva: u32) -> Result<(), ImportError> {
        let key = self.module_key_by_thunk_rva(rva).ok_or(ImportError::ModuleThunkNotFound(rva))?;
        self.modules.remove(&key);
        Ok(())
    }

    pub fn cut_thunk(&mut self, rva: u32, pointer_size: usize) -> Result<(), ImportError> {
        validate_pointer_size(pointer_size)?;
        let pointer_size = u32::try_from(pointer_size)
            .map_err(|_| ImportError::Overflow("converting pointer size to u32"))?;
        let key = self.module_key_by_range_rva(rva, pointer_size)?
            .ok_or(ImportError::ModuleThunkNotFound(rva))?;
        let module = self.modules
            .get_mut(&key)
            .ok_or(ImportError::ModuleThunkNotFound(rva))?;

        if !module.thunks.contains_key(&rva) {
            return Err(ImportError::FunctionNotFound(rva));
        }

        let module_end = module
            .first_thunk
            .checked_add(module.nb_thunks.saturating_mul(pointer_size))
            .ok_or(ImportError::Overflow("computing cut import module range"))?;
        let second_first_thunk = rva
            .checked_add(pointer_size)
            .ok_or(ImportError::Overflow("computing cut import module tail"))?;
        let first_nb_thunks = rva
            .checked_sub(module.first_thunk)
            .ok_or(ImportError::Overflow("computing cut import module head"))?
            / pointer_size;
        let second_nb_thunks = module_end.saturating_sub(second_first_thunk) / pointer_size;
        let second_rvas = module
            .thunks
            .range(second_first_thunk..module_end)
            .map(|(rva, _)| *rva)
            .collect::<Vec<_>>();
        let mut second_thunks = BTreeMap::new();

        module.thunks.remove(&rva);
        for rva in second_rvas {
            if let Some(thunk) = module.thunks.remove(&rva) {
                second_thunks.insert(rva, thunk);
            }
        }
        module.nb_thunks = first_nb_thunks;

        let remove_original = module.nb_thunks == 0 && module.thunks.is_empty();
        if remove_original {
            self.modules.remove(&key);
        }
        if second_nb_thunks != 0 {
            let name = self.cut_module_name(second_first_thunk);
            self.modules.insert(
                module_key(&name),
                ImportModule {
                    name,
                    first_thunk: second_first_thunk,
                    nb_thunks: second_nb_thunks,
                    thunks: second_thunks,
                },
            );
        }

        Ok(())
    }

    pub fn rename_module_containing_thunk(&mut self, rva: u32, name: &str) -> Result<(), ImportError> {
        validate_cstr(name)?;

        let old_key = self.module_key_by_thunk_rva(rva).ok_or(ImportError::ModuleThunkNotFound(rva))?;
        let new_key = module_key(name);

        if old_key == new_key {
            if let Some(module) = self.modules.get_mut(&old_key) {
                module.name = name.to_string();
            }
            return Ok(());
        }

        if self.modules.contains_key(&new_key) {
            return Err(ImportError::ModuleNameCollision(name.to_string()));
        }

        if let Some(mut module) = self.modules.remove(&old_key) {
            module.name = name.to_string();
            self.modules.insert(new_key, module);
        }

        Ok(())
    }

    pub fn imports(&self) -> Vec<ImportEntry> {
        let mut imports = self
            .modules
            .values()
            .flat_map(|module| {
                module.thunks.values().map(|thunk| match &thunk.target {
                    ImportTarget::Name { hint, ordinal, name } => ImportEntry {
                        module_name: module.name.clone(),
                        rva: thunk.rva,
                        name: Some(name.clone()),
                        ordinal: *ordinal,
                        hint: Some(*hint),
                        valid: thunk.valid,
                        address: None,
                        confidence: import_confidence(thunk),
                        evidence: thunk.evidence.clone(),
                    },
                    ImportTarget::Ordinal(ordinal) => ImportEntry {
                        module_name: module.name.clone(),
                        rva: thunk.rva,
                        name: None,
                        ordinal: Some(*ordinal),
                        hint: None,
                        valid: thunk.valid,
                        address: None,
                        confidence: import_confidence(thunk),
                        evidence: thunk.evidence.clone(),
                    },
                    ImportTarget::Unknown(address) => ImportEntry {
                        module_name: module.name.clone(),
                        rva: thunk.rva,
                        name: None,
                        ordinal: None,
                        hint: None,
                        valid: thunk.valid,
                        address: Some(*address),
                        confidence: import_confidence(thunk),
                        evidence: thunk.evidence.clone(),
                    },
                })
            })
            .collect::<Vec<_>>();

        imports.sort_by(|left, right| {
            left.rva
                .cmp(&right.rva)
                .then_with(|| left.module_name.cmp(&right.module_name))
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.ordinal.cmp(&right.ordinal))
                .then_with(|| left.address.cmp(&right.address))
        });
        imports
    }

    pub fn modules(&self) -> Vec<ImportModuleEntry> {
        self.modules
            .values()
            .map(|module| ImportModuleEntry {
                module_name: module.name.clone(),
                first_thunk: module.first_thunk,
                nb_thunks: module.nb_thunks,
                function_count: module.thunks.len(),
                valid_function_count: module.thunks.values().filter(|thunk| thunk.valid).count(),
            })
            .collect()
    }

    pub fn issues(&self, pointer_size: usize) -> Result<Vec<ImportIssue>, ImportError> {
        validate_pointer_size(pointer_size)?;
        let pointer_size = u32::try_from(pointer_size)
            .map_err(|_| ImportError::Overflow("converting pointer size to u32"))?;
        let mut issues = Vec::new();

        for module in self.modules.values() {
            let module_range_end = import_module_range_end(module, pointer_size)?;
            if module_range_end.is_none() {
                issues.push(import_issue_from_module_range(ImportIssueKind::EmptyModuleRange, module, module.first_thunk, None, None));
            }

            if !module.thunks.values().any(|thunk| thunk.valid) {
                issues.push(ImportIssue {
                    kind: ImportIssueKind::ModuleWithoutValidFunctions,
                    severity: ImportIssueKind::ModuleWithoutValidFunctions.severity(),
                    rva: module.first_thunk,
                    module_name: module.name.clone(),
                    name: None,
                    ordinal: None,
                    address: None,
                    next_rva: None,
                    next_module_name: None,
                });
            }

            if module.thunks.values().filter(|thunk| thunk.valid).count() == 1 {
                if let Some(thunk) = module.thunks.values().find(|thunk| thunk.valid) {
                    issues.push(import_issue_from_thunk(ImportIssueKind::SingletonValidFunction, module, thunk));
                }
            }

            let mut targets = BTreeMap::<ImportTargetKey, &ImportThunk>::new();
            for thunk in module.thunks.values().filter(|thunk| thunk.valid) {
                match targets.entry(import_target_key(&thunk.target)) {
                    Entry::Vacant(entry) => {
                        entry.insert(thunk);
                    }
                    Entry::Occupied(entry) => {
                        issues.push(import_issue_from_thunk_pair(
                            ImportIssueKind::DuplicateImportTargetInModule,
                            module,
                            thunk,
                            entry.get(),
                        ));
                    }
                }
            }

            for run in repeated_import_target_runs(module, pointer_size) {
                if let Some(issue) = import_issue_from_repeated_import_target_run(module, run) {
                    issues.push(issue);
                }
            }

            for run in missing_thunk_runs(module, pointer_size)? {
                issues.push(import_issue_from_missing_thunk_run(
                    ImportIssueKind::SparseModuleRange,
                    module,
                    run.first_missing_rva,
                    run.next_thunk_rva,
                ));

                if let Some(thunk) = run
                    .previous_thunk_rva
                    .and_then(|rva| module.thunks.get(&rva))
                    .filter(|thunk| thunk.valid)
                {
                    issues.push(import_issue_from_thunk_and_gap(
                        ImportIssueKind::FunctionAdjacentToRangeGap,
                        module,
                        thunk,
                        run.first_missing_rva,
                    ));
                }

                if let Some(thunk) = run
                    .next_thunk_rva
                    .and_then(|rva| module.thunks.get(&rva))
                    .filter(|thunk| thunk.valid)
                {
                    issues.push(import_issue_from_thunk_and_gap(
                        ImportIssueKind::FunctionAdjacentToRangeGap,
                        module,
                        thunk,
                        run.last_missing_rva,
                    ));
                }
            }

            for thunk in module.thunks.values() {
                if !thunk.valid {
                    issues.push(import_issue_from_thunk(ImportIssueKind::InvalidFunction, module, thunk));
                }

                if let Some(module_range_end) = module_range_end {
                    if thunk.rva < module.first_thunk || thunk.rva >= module_range_end {
                        issues.push(import_issue_from_thunk(ImportIssueKind::ThunkOutsideModuleRange, module, thunk));
                    } else if (thunk.rva - module.first_thunk) % pointer_size != 0 {
                        issues.push(import_issue_from_thunk(ImportIssueKind::ThunkMisalignedInModuleRange, module, thunk));
                    }
                }
            }
        }

        let mut ranges = Vec::new();
        for module in self.modules.values() {
            if let Some(end_rva) = import_module_range_end(module, pointer_size)? {
                ranges.push((module.first_thunk, end_rva, module));
            }
        }
        ranges.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.cmp(&right.1))
                .then_with(|| left.2.name.cmp(&right.2.name))
        });
        let mut active_range = None;
        for (range_start, range_end, module) in ranges {
            if let Some((_active_start, active_end, active_module)) = active_range {
                if range_start < active_end {
                    issues.push(import_issue_from_module_range(
                        ImportIssueKind::OverlappingModuleRange,
                        active_module,
                        range_start,
                        Some(active_end),
                        Some(module),
                    ));
                }
            }

            active_range = match active_range {
                Some((active_start, active_end, active_module)) if active_end >= range_end => {
                    Some((active_start, active_end, active_module))
                }
                _ => Some((range_start, range_end, module)),
            };
        }

        let mut thunk_rvas = BTreeMap::<u32, ImportEntry>::new();
        for entry in self.imports() {
            match thunk_rvas.entry(entry.rva) {
                Entry::Vacant(vacant) => {
                    vacant.insert(entry);
                }
                Entry::Occupied(occupied) => {
                    issues.push(import_issue_from_import_entry_pair(
                        ImportIssueKind::DuplicateThunkRvaAcrossModules,
                        &entry,
                        occupied.get(),
                    ));
                }
            }
        }

        for pair in self.imports().windows(2) {
            let left = &pair[0];
            let right = &pair[1];
            if module_key(&left.module_name) == module_key(&right.module_name) {
                continue;
            }

            let Some(expected_next_rva) = left.rva.checked_add(pointer_size) else {
                continue;
            };
            if expected_next_rva != right.rva {
                continue;
            }

            issues.push(ImportIssue {
                kind: ImportIssueKind::AdjacentDifferentModule,
                severity: ImportIssueKind::AdjacentDifferentModule.severity(),
                rva: left.rva,
                module_name: left.module_name.clone(),
                name: left.name.clone(),
                ordinal: left.ordinal,
                address: left.address,
                next_rva: Some(right.rva),
                next_module_name: Some(right.module_name.clone()),
            });
        }

        sort_import_issues(&mut issues);

        Ok(issues)
    }

    pub fn issues_with_exports(
        &self,
        pointer_size: usize,
        exports: &[&ExportTable],
    ) -> Result<Vec<ImportIssue>, ImportError> {
        let mut issues = self.issues(pointer_size)?;

        self.add_export_validation_issues(&mut issues, exports, None);
        sort_import_issues(&mut issues);

        Ok(issues)
    }

    pub fn issues_with_export_map(&self, pointer_size: usize, exports: &crate::pe::export_map::ExportMap) -> Result<Vec<ImportIssue>, ImportError> {
        let mut issues = self.issues(pointer_size)?;
        self.add_export_validation_issues(&mut issues, &exports.tables().collect::<Vec<_>>(), Some(exports.api_set_map()));
        sort_import_issues(&mut issues);
        Ok(issues)
    }

    pub fn recover_iat(
        &mut self,
        iat_rva: u32,
        iat_data: &[u8],
        pointer_size: usize,
        address_resolve_mode: ImportAddressResolveMode,
        exports: &[&ExportTable],
    ) -> Result<usize, ImportError> {
        recover_iat(self, iat_rva, iat_data, pointer_size, address_resolve_mode, exports)
    }

    pub fn recover_iat_with_options(
        &mut self,
        iat_rva: u32,
        iat_data: &[u8],
        pointer_size: usize,
        address_resolve_options: ImportAddressResolveOptions,
        exports: &[&ExportTable],
    ) -> Result<usize, ImportError> {
        recover_iat_with_options(self, iat_rva, iat_data, pointer_size, address_resolve_options, exports)
    }

    pub fn recover_iat_with_recovery_options(
        &mut self,
        iat_rva: u32,
        iat_data: &[u8],
        pointer_size: usize,
        options: RecoverIatOptions,
        exports: &[&ExportTable],
    ) -> Result<usize, ImportError> {
        recover_iat_with_recovery_options(self, iat_rva, iat_data, pointer_size, options, exports)
    }

    pub fn recover_iat_with_evidence(
        &mut self,
        iat_rva: u32,
        iat_data: &[u8],
        pointer_size: usize,
        options: RecoverIatOptions,
        evidence_kind: ImportEvidenceKind,
        exports: &[&ExportTable],
    ) -> Result<usize, ImportError> {
        recover_iat_with_evidence(self, iat_rva, iat_data, pointer_size, options, evidence_kind, exports)
    }

    pub fn recover_iat_with_traced_thunks(
        &mut self,
        iat_rva: u32,
        iat_data: &[u8],
        mapped_image_data: &[u8],
        image_base: Option<u64>,
        pointer_size: usize,
        address_resolve_options: ImportAddressResolveOptions,
        max_depth: usize,
        exports: &[&ExportTable],
    ) -> Result<usize, ImportError> {
        recover_iat_with_traced_thunks(
            self,
            iat_rva,
            iat_data,
            mapped_image_data,
            image_base,
            pointer_size,
            address_resolve_options,
            max_depth,
            exports,
        )
    }

    pub fn recover_iat_with_traced_thunks_and_recovery_options(
        &mut self,
        iat_rva: u32,
        iat_data: &[u8],
        mapped_image_data: &[u8],
        image_base: Option<u64>,
        pointer_size: usize,
        options: RecoverIatOptions,
        max_depth: usize,
        exports: &[&ExportTable],
    ) -> Result<usize, ImportError> {
        recover_iat_with_traced_thunks_and_recovery_options(
            self,
            iat_rva,
            iat_data,
            mapped_image_data,
            image_base,
            pointer_size,
            options,
            max_depth,
            exports,
        )
    }

    pub fn recover_iat_with_traced_thunks_and_evidence(
        &mut self,
        iat_rva: u32,
        iat_data: &[u8],
        mapped_image_data: &[u8],
        image_base: Option<u64>,
        pointer_size: usize,
        options: RecoverIatOptions,
        max_depth: usize,
        evidence_kind: ImportEvidenceKind,
        exports: &[&ExportTable],
    ) -> Result<usize, ImportError> {
        recover_iat_with_traced_thunks_and_evidence(
            self,
            iat_rva,
            iat_data,
            mapped_image_data,
            image_base,
            pointer_size,
            options,
            max_depth,
            evidence_kind,
            exports,
        )
    }

    pub fn recover_iat_slots_with_recovery_options(
        &mut self,
        slots: &[ImportAddressSlot],
        pointer_size: usize,
        options: RecoverIatOptions,
        exports: &[&ExportTable],
    ) -> Result<usize, ImportError> {
        recover_iat_slots_with_recovery_options(self, slots, pointer_size, options, exports)
    }

    pub fn recover_iat_from_code_references(
        &mut self,
        references: &[ImportCodeReference],
        pointer_size: usize,
    ) -> Result<usize, ImportError> {
        recover_iat_from_code_references(self, references, pointer_size)
    }

    pub(super) fn valid_modules(&self) -> Vec<&ImportModule> {
        self.modules
            .values()
            .filter(|module| module.thunks.values().any(|thunk| thunk.valid))
            .collect()
    }

    pub(super) fn has_thunk_rva(&self, rva: u32) -> bool {
        self.modules.values().any(|module| module.thunks.contains_key(&rva))
    }

    fn function_mut(&mut self, rva: u32) -> Option<&mut ImportThunk> {
        self.modules.values_mut().find_map(|module| module.thunks.get_mut(&rva))
    }

    fn module_key_by_thunk_rva(&self, rva: u32) -> Option<String> {
        self.modules
            .iter()
            .find(|(_, module)| module.thunks.contains_key(&rva))
            .map(|(key, _)| key.clone())
    }

    fn module_key_by_range_rva(&self, rva: u32, pointer_size: u32) -> Result<Option<String>, ImportError> {
        for (key, module) in &self.modules {
            if module.nb_thunks == 0 {
                continue;
            }

            let range_size = module.nb_thunks.saturating_mul(pointer_size);
            let end = module
                .first_thunk
                .checked_add(range_size)
                .ok_or(ImportError::Overflow("computing import module range"))?;
            if rva < module.first_thunk || rva >= end {
                continue;
            }
            if (rva - module.first_thunk) % pointer_size == 0 {
                return Ok(Some(key.clone()));
            }
        }

        Ok(None)
    }

    pub(super) fn cut_module_name(&self, first_thunk: u32) -> String {
        let base = format!("?0x{first_thunk:x}");
        if !self.modules.contains_key(&module_key(&base)) {
            return base;
        }

        for index in 2usize.. {
            let name = format!("{base}#{index}");
            if !self.modules.contains_key(&module_key(&name)) {
                return name;
            }
        }

        unreachable!("usize module suffix search cannot exhaust")
    }

    fn add_export_validation_issues(&self, issues: &mut Vec<ImportIssue>, exports: &[&ExportTable], api_sets: Option<&crate::pe::api_set::ApiSetMap>) {
        let mut export_tables = BTreeMap::new();
        for export_table in exports {
            export_tables.insert(module_key(&export_table.module_name), *export_table);
        }

        for module in self.modules.values() {
            if !module.thunks.values().any(|thunk| thunk.valid) {
                continue;
            }

            let export_table = export_tables.get(&module_key(&module.name)).or_else(|| {
                let host = api_sets?.resolve_contract(&module.name)?;
                export_tables.get(&module_key(host))
            });
            let Some(export_table) = export_table else {
                issues.push(import_issue_from_module_range(
                    ImportIssueKind::ImportModuleMissingExportTable,
                    module,
                    module.first_thunk,
                    None,
                    None,
                ));
                continue;
            };

            for thunk in module.thunks.values().filter(|thunk| thunk.valid) {
                match &thunk.target {
                    ImportTarget::Name { name, .. } if export_table.resolve_name(name).is_none() => {
                        issues.push(import_issue_from_thunk(ImportIssueKind::ImportTargetMissingFromExports, module, thunk));
                    }
                    ImportTarget::Ordinal(ordinal) => match export_table.resolve_ordinal(*ordinal as u32) {
                        Some(symbol) if symbol.name.is_some() => {
                            issues.push(import_issue_from_thunk(ImportIssueKind::OrdinalOnlyImportHasNamedExport, module, thunk));
                        }
                        Some(_) => {}
                        None => {
                            issues.push(import_issue_from_thunk(ImportIssueKind::ImportTargetMissingFromExports, module, thunk));
                        }
                    },
                    ImportTarget::Unknown(_) => {
                        issues.push(import_issue_from_thunk(ImportIssueKind::ImportTargetMissingFromExports, module, thunk));
                    }
                    _ => {}
                }
            }
        }
    }

    pub(super) fn upsert_module_range(
        &mut self,
        name: &str,
        first_thunk: u32,
        last_thunk: u32,
        pointer_size: usize,
    ) -> Result<(), ImportError> {
        validate_cstr(name)?;

        let key = module_key(name);
        let pointer_size = u32::try_from(pointer_size)
            .map_err(|_| ImportError::Overflow("converting pointer size to u32"))?;

        match self.modules.entry(key) {
            Entry::Occupied(mut entry) => {
                let module = entry.get_mut();
                if module.nb_thunks == 0 {
                    module.first_thunk = first_thunk;
                    module.nb_thunks = thunk_count(first_thunk, last_thunk, pointer_size)?;
                    return Ok(());
                }

                let old_last_thunk = module
                    .first_thunk
                    .checked_add(module.nb_thunks.saturating_sub(1).saturating_mul(pointer_size))
                    .ok_or(ImportError::Overflow("computing import module thunk range"))?;
                let first_thunk = module.first_thunk.min(first_thunk);
                let last_thunk = old_last_thunk.max(last_thunk);

                module.first_thunk = first_thunk;
                module.nb_thunks = thunk_count(first_thunk, last_thunk, pointer_size)?;
            }
            Entry::Vacant(entry) => {
                entry.insert(ImportModule {
                    name: name.to_string(),
                    first_thunk,
                    nb_thunks: thunk_count(first_thunk, last_thunk, pointer_size)?,
                    thunks: BTreeMap::new(),
                });
            }
        }

        Ok(())
    }
}

fn import_confidence(thunk: &ImportThunk) -> u8 {
    thunk
        .evidence
        .iter()
        .map(|evidence| evidence.confidence)
        .max()
        .unwrap_or(if thunk.valid { 100 } else { 0 })
}
