import Foundation
import ForensicsCore

@MainActor
enum FilesystemFormatting {
    private static var dateFormatters: [String: DateFormatter] = [:]

    static func timestamp(_ seconds: Int64?, in timezone: String) -> String {
        guard let seconds else { return "—" }
        guard (-62_135_596_800...253_402_300_799).contains(seconds) else { return "Unix \(seconds)" }
        let formatter: DateFormatter
        if let existing = dateFormatters[timezone] {
            formatter = existing
        } else {
            let created = DateFormatter()
            created.locale = Locale(identifier: "en_US_POSIX")
            created.timeZone = TimeZone(identifier: timezone) ?? TimeZone(secondsFromGMT: 0)
            created.dateFormat = "yyyy-MM-dd HH:mm:ss"
            dateFormatters[timezone] = created
            formatter = created
        }
        return formatter.string(from: Date(timeIntervalSince1970: TimeInterval(seconds)))
    }

    static func status(_ status: EngineTerminalStatus) -> String {
        switch status {
        case .completed: "Analysis completed"
        case .partial: "Partial result — review warnings"
        case .failed: "Analysis failed"
        case .cancelled: "Analysis cancelled"
        }
    }

    static func rawTime(_ seconds: Int64?, nanoseconds: Int32) -> String {
        guard let seconds else { return "Unavailable" }
        return "\(seconds) seconds + \(nanoseconds) ns"
    }
}
