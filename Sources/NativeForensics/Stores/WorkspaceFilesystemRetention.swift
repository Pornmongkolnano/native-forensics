import Foundation
import ForensicsCore

extension WorkspaceStore {
    /// Only memory is evicted; immutable case artifacts stay available for reload.
    @discardableResult
    func retainFilesystemResult(_ result: EnumerationResult, evidenceID: UUID,
                                cost: FilesystemListingStringCost) -> Bool {
        let insertion = filesystemListingRetention.insert(evidenceID: evidenceID, cost: cost)
        let retained = filesystemListingRetention.retainedEvidenceIDs
        filesystemResults = filesystemResults.filter { retained.contains($0.key) }
        filesystemListingGenerations = filesystemListingGenerations.filter { retained.contains($0.key) }
        if insertion.retained {
            filesystemResults[evidenceID] = result
            filesystemListingGenerations[evidenceID] = UUID()
        }
        return insertion.retained
    }
}
