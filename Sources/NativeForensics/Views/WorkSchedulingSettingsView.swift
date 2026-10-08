import ForensicsCore
import SwiftUI

struct WorkSchedulingSettingsView: View {
    @State private var monitor = WorkEnergyMonitor.shared

    var body: some View {
        Section("Work and energy") {
            Picker("New workflow priority", selection: Binding<ForensicEnergyMode>(
                get: { monitor.mode },
                set: { (mode: ForensicEnergyMode) in monitor.selectMode(mode) }
            )) {
                Text("Automatic").tag(ForensicEnergyMode.automatic)
                Text("Conserve energy").tag(ForensicEnergyMode.conserveEnergy)
            }
            Text("One heavy workflow runs across all windows. Automatic uses lower priority on battery, in Low Power Mode or when thermals rise. Conserve energy always gives new workers lower priority.")
                .font(.caption).foregroundStyle(.secondary)
            LabeledContent("Next worker", value: monitor.nextPolicy.priority == .utility ? "Utility priority" : "User-initiated priority")
            LabeledContent("Power source", value: powerLabel)
            LabeledContent("Thermal state", value: monitor.context.thermalState.rawValue.capitalized)
            Text("A changed policy applies to the next admitted workflow. Running verification, cleanup and saves finish under their existing ownership. Evidence and content limits stay the same.")
                .font(.caption).foregroundStyle(.secondary)
            Text("Power-source samples refresh about every 30 seconds, with scheduling delay. Battery-life and physical M5 measurements remain pending.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .task { monitor.start(); monitor.refresh() }
    }

    private var powerLabel: String {
        switch monitor.context.powerSource {
        case .externalPower: "External power"
        case .battery: "Battery"
        case .unknown: "Unavailable"
        }
    }
}
