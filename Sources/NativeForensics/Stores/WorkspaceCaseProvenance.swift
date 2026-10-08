import Foundation
import ForensicsCore

extension WorkspaceStore {
    /// Only an explicit user action migrates a case. The existing owned derived
    /// task is included in window-close/termination drainage and busy guards.
    func changeCaseProvenanceFormat(upgrade: Bool) {
        guard !isBusy, !isClosing, caseWork.canChangeSelection, recovery.canChangeSelection,
              let forensicCase = currentCase else { return }
        let id = UUID()
        derivedNavigationID = id
        statusMessage = upgrade ? "Preserving the earlier manifest and upgrading provenance…" : "Verifying the earlier manifest before restoring…"
        derivedNavigationTask = Task { [weak self] in
            guard let self else { return }
            defer {
                if self.derivedNavigationID == id {
                    self.derivedNavigationID = nil; self.derivedNavigationTask = nil
                }
            }
            do {
                let worker = Task.detached(priority: .utility) {
                    try Task.checkCancellation()
                    return try upgrade ? CaseStore.migrateToSchema2(forensicCase) : CaseStore.rollbackSchema2Migration(forensicCase)
                }
                // A commit is not undone by cancellation. Await its concrete
                // outcome and let closing drain this owner before teardown.
                let updated = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
                guard self.currentCase?.manifest.id == updated.manifest.id,
                      self.currentCase?.bundleURL == updated.bundleURL else { return }
                self.currentCase = updated
                if !self.isClosing {
                    self.caseIntegrity.configure(forensicCase: updated)
                    self.refreshDerivedWorkspaces()
                    self.statusMessage = upgrade ? "Case provenance format 2 saved; earlier manifest and existing records preserved." : "Exact earlier manifest restored; existing records preserved."
                }
            } catch is CancellationError {
                self.statusMessage = "Case format operation cancelled before publication."
            } catch {
                self.errorMessage = error.localizedDescription
                self.statusMessage = "Case format operation did not report confirmed completion. Reopen the case before retrying."
            }
        }
    }
}
