import Foundation
import ForensicsCore

enum EvidenceFormatting {
    static func bytes(_ count: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: count, countStyle: .file)
    }

    static func container(_ format: ImageContainer) -> String {
        switch format {
        case .raw: "Raw image"
        case .ewf: "EWF container"
        case .unknown: "Unrecognized container"
        }
    }
}
