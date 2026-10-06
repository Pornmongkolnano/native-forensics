import SwiftUI

struct WorkbenchSettingsView: View {
    @AppStorage("workbenchAppearance") private var appearance = "system"

    var body: some View {
        Form {
            Section {
                Picker("Appearance", selection: $appearance) {
                    Text("System").tag("system")
                    Text("Light").tag("light")
                    Text("Dark").tag("dark")
                }
                .pickerStyle(.segmented)
                Text("Follow macOS, or choose an appearance for this workbench.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 420, height: 150)
    }
}
