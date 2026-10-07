import Foundation

/// An examiner's assessment is not a decoder result or proof of deletion.
public enum RecoveryAssessment: String, Codable, Sendable, CaseIterable {
    case notReviewed, accessible, damaged, unsupported, unknown
}

public struct RecoveryAnnotation: Codable, Sendable, Equatable {
    public let artifactID: UUID
    public let assessment: RecoveryAssessment
    public let note: String
    public static let maximumNoteBytes = 8 * 1_024

    public init(artifactID: UUID, assessment: RecoveryAssessment = .notReviewed, note: String = "") {
        self.artifactID = artifactID; self.assessment = assessment; self.note = note
    }

    func validate() throws {
        guard note.utf8.count <= Self.maximumNoteBytes, !note.utf8.contains(0) else {
            throw RecoveryError.invalidResult
        }
    }
}
