import AppKit
import CryptoKit
import Darwin
import Foundation
import ForensicsCore

/// Standalone distribution helper: no NativeForensics UI, engine, Python,
/// Homebrew or developer tools are needed on the receiving Mac.
@main
struct AutopsyUDFExport {
    @MainActor
    static func main() async {
        let arguments = Array(CommandLine.arguments.dropFirst())
        let interactive = arguments == ["--interactive"]
        do {
            if arguments == ["--help"] || arguments.isEmpty {
                print(usage); return
            }
            if arguments.count == 2, arguments[0] == "--self-test" {
                try await selfTest(fixtureURL: URL(fileURLWithPath: arguments[1])); return
            }
            let input: URL, destination: URL
            if interactive {
                NSApplication.shared.setActivationPolicy(.accessory)
                NSApplication.shared.activate(ignoringOtherApps: true)
                let select = NSOpenPanel()
                select.title = "เลือก image UDF (.dd, .img, .raw)"
                select.message = "เลือกไฟล์ image ต้นฉบับ โปรแกรมอ่านอย่างเดียวและส่งออกสำเนาใหม่สำหรับ Autopsy"
                select.canChooseFiles = true; select.canChooseDirectories = false
                select.allowsMultipleSelection = false
                guard select.runModal() == .OK, let selected = select.url else { return }
                input = selected
                let output = NSOpenPanel()
                output.title = "เลือกโฟลเดอร์สำหรับเก็บผลส่งออก"
                output.message = "จะสร้างโฟลเดอร์ UDF-For-Autopsy ใหม่ภายในตำแหน่งนี้ โดยไม่ทับไฟล์เดิม"
                output.canChooseFiles = false; output.canChooseDirectories = true
                output.canCreateDirectories = true; output.allowsMultipleSelection = false
                guard output.runModal() == .OK, let parent = output.url else { return }
                let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
                destination = parent.appendingPathComponent("UDF-For-Autopsy-\(stamp)-\(UUID().uuidString.prefix(8))", isDirectory: true)
            } else {
                guard arguments.count == 4, arguments[0] == "--source", arguments[2] == "--output",
                      !arguments[1].isEmpty, !arguments[3].isEmpty else { throw CommandError.arguments }
                input = URL(fileURLWithPath: arguments[1])
                destination = URL(fileURLWithPath: arguments[3])
            }
            let result = try await UDFLogicalFilesExporter.export(sourceURL: input, to: destination, progress: { progress in
                if progress.stage.hasPrefix("Exporting") || progress.stage.hasPrefix("Reading UDF") || progress.stage.hasPrefix("Complete") {
                    FileHandle.standardError.write(Data("\(progress.stage)\n".utf8))
                }
            })
            print("Exported \(result.entries.count) verified files to \(result.destinationPath)")
            print("Source SHA-256: \(result.sourceSHA256)")
            print("Import only: \(destination.appendingPathComponent("LogicalFiles").path)")
            if interactive {
                NSWorkspace.shared.activateFileViewerSelecting([destination.appendingPathComponent("READ-ME-FIRST.txt")])
                let alert = NSAlert()
                alert.messageText = "ส่งออกไฟล์ UDF สำเร็จ \(result.entries.count) ไฟล์"
                alert.informativeText = "Autopsy > Add Data Source > Logical Files > Local files and folders > Add และเลือก LogicalFiles ในโฟลเดอร์นี้\n\nไม่ติ๊กนำเข้าวันเวลาจาก Mac: เวลาต้นฉบับและประวัติ VAT อยู่ใน Reports. เก็บผลส่งออกไว้ที่เดิมหลังนำเข้า."
                alert.addButton(withTitle: "ตกลง"); alert.runModal()
            }
        } catch {
            let detail = "UDF export failed: \(error.localizedDescription)"
            FileHandle.standardError.write(Data("\(detail)\n\(usage)\n".utf8))
            if interactive {
                let alert = NSAlert(); alert.alertStyle = .warning
                alert.messageText = "ส่งออก UDF ไม่สำเร็จ"
                alert.informativeText = "\(error.localizedDescription)\n\nรองรับ raw 2048-byte UDF 2.01 พร้อม VAT ตามขอบเขตที่ทดสอบ. ไม่ได้แก้ไข image ต้นฉบับ. ตรวจสอบว่ามีโฟลเดอร์ปลายทางและ Reports/manifest.json ที่สมบูรณ์หรือไม่: ข้อผิดพลาด flush หลังเผยแพร่อาจเกิดเมื่อโฟลเดอร์สมบูรณ์แสดงแล้ว."
                alert.addButton(withTitle: "ตกลง"); alert.runModal()
            }
            Darwin.exit(1)
        }
    }

    private static func selfTest(fixtureURL: URL) async throws {
        // This distribution fixture contains only generated public text data.
        let fixture = try await ImageInspector.inspect(url: fixtureURL, progress: { _ in })
        guard fixture.byteCount == 400 * 2_048,
              fixture.sha256 == "92543dd97a8a35d7aea0e7b381f6a3f5403dcbf0cc5101b65f845353847fd266" else { throw CommandError.fixture }
        let parent = FileManager.default.temporaryDirectory.appendingPathComponent("Autopsy-UDF-SelfTest-" + UUID().uuidString).resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let output = parent.appendingPathComponent("Verified")
        let result = try await UDFLogicalFilesExporter.export(sourceURL: fixtureURL, to: output)
        let expected = [
            "/current.txt": Data("Current file\n".utf8),
            "/deleted/note.dat": Data("This historical payload uses two noncontiguous recorded extents.\n".utf8)
        ]
        guard result.entries.count == 2, Set(result.entries.map(\.originalPath)) == Set(expected.keys) else { throw CommandError.fixture }
        for entry in result.entries {
            guard let bytes = expected[entry.originalPath], entry.byteCount == bytes.count,
                  entry.sha256 == SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined(),
                  try Data(contentsOf: output.appendingPathComponent(entry.outputRelativePath)) == bytes else { throw CommandError.fixture }
        }
        let history = try JSONDecoder().decode(UDFInspectionResult.self,
            from: Data(contentsOf: output.appendingPathComponent("Reports/udf-history.json")))
        guard history.snapshots.count == 2, history.entries.contains(where: {
            $0.originalPath == "/deleted/note.dat" && $0.state == .historicalDeletedAncestor && $0.sourceExtents.count == 2
        }) else { throw CommandError.fixture }
        // A malformed optical anchor must never publish a successful directory.
        var malformed = try Data(contentsOf: fixtureURL)
        malformed[256 * 2_048 + 4] ^= 1
        let invalid = parent.appendingPathComponent("Malformed.dd")
        try malformed.write(to: invalid, options: .withoutOverwriting)
        let rejected = parent.appendingPathComponent("MustNotPublish")
        do {
            _ = try await UDFLogicalFilesExporter.export(sourceURL: invalid, to: rejected)
            throw CommandError.fixture
        } catch let error as UDFError {
            guard case .malformed = error else { throw CommandError.fixture }
            guard !FileManager.default.fileExists(atPath: rejected.path) else { throw CommandError.fixture }
        }
        let after = try await ImageInspector.inspect(url: fixtureURL, progress: { _ in })
        guard after.sha256 == fixture.sha256, after.byteCount == fixture.byteCount else { throw CommandError.fixture }
        print("PASS: 2 exact synthetic payloads, 2 VAT states, deleted ancestor, noncontiguous extents, malformed-source rejection, unchanged fixture.")
        print("Self-test receipts: \(output.path)")
    }

    private static let usage = """
    Usage:
      AutopsyUDFExport --interactive
      AutopsyUDFExport --source /path/image.dd --output /path/NEW-output-directory
      AutopsyUDFExport --self-test /path/synthetic-udf.dd
    Bounded UDF 2.01/VAT -> derived Logical Files + provenance reports.
    The original image is read-only. Existing output is never overwritten.
    """
    private enum CommandError: Error, LocalizedError {
        case arguments, fixture
        var errorDescription: String? {
            switch self {
            case .arguments: "Invalid arguments. Select --interactive or specify --source and a new --output directory."
            case .fixture: "The synthetic UDF distribution self-test failed its expected payload or safety controls."
            }
        }
    }
}
