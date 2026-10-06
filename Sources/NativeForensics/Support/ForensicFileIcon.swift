import AppKit
import ForensicsCore
import SwiftUI

/// A lightweight filename hint. Icons never establish a file's content type.
struct ForensicFileIcon: View {
    let file: FilesystemEntry
    var size: CGFloat = 18
    var isSelected = false

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: size, weight: .medium))
            .foregroundStyle(isSelected ? Color(nsColor: .alternateSelectedControlTextColor)
                             : file.isDeleted ? Color.orange : tint)
            .frame(width: size + 4, height: size + 4)
            .overlay(alignment: .bottomTrailing) {
                if file.isDeleted {
                    Image(systemName: "minus.circle.fill")
                        .font(.system(size: max(7, size * 0.48), weight: .bold))
                        .symbolRenderingMode(.palette)
                        .foregroundStyle(.orange, .background)
                        .offset(x: 2, y: 2)
                }
            }
            .accessibilityHidden(true)
    }

    private var filenameExtension: String {
        FilesystemCategory.filenameExtension(for: file)
    }

    private var symbol: String {
        if file.isDirectory { return "folder.fill" }
        if file.name.hasPrefix("$") { return "doc.badge.gearshape" }
        switch FilesystemCategory.category(for: file) {
        case .documents:
            return ["txt", "log", "md", "csv", "json", "xml", "yaml", "yml"].contains(filenameExtension)
                ? "doc.plaintext" : "doc.richtext"
        case .images: return "photo"
        case .archives: return "doc.zipper"
        case .media:
            return ["mp3", "wav", "flac", "aac", "m4a", "ogg", "aiff"].contains(filenameExtension)
                ? "waveform" : "film"
        default: return "doc"
        }
    }

    private var tint: Color {
        if file.isDirectory { return .blue }
        if file.name.hasPrefix("$") { return .secondary }
        switch FilesystemCategory.category(for: file) {
        case .documents: return .indigo
        case .images: return .purple
        case .archives: return .brown
        case .media: return .teal
        default: return .secondary
        }
    }
}
