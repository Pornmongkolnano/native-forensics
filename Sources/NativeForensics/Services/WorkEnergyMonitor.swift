import Foundation
import ForensicsCore
import IOKit.ps
import Observation
import OSLog

/// Reads public power/thermal APIs. It changes priority for the next admission;
/// it never stops a running source verification, cleanup or publication.
@MainActor
@Observable
final class WorkEnergyMonitor {
    static let shared = WorkEnergyMonitor()
    private(set) var mode: ForensicEnergyMode
    private(set) var context: ForensicEnergyContext
    private(set) var sampledAt: Date?
    var nextPolicy: ForensicWorkPolicy { .decide(mode: mode, context: context) }
    @ObservationIgnored private let scheduler: ForensicWorkScheduler
    @ObservationIgnored private let sample: @MainActor () -> ForensicEnergyContext
    @ObservationIgnored private var observers: [NSObjectProtocol] = []
    @ObservationIgnored private var timer: Timer?
    @ObservationIgnored private var publishTask: Task<Void, Never>?
    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let logger = Logger(subsystem: "io.github.pornmongkolnano.nativeforensics", category: "WorkScheduling")

    init(scheduler: ForensicWorkScheduler = .shared, defaults: UserDefaults = .standard,
         sample: @escaping @MainActor () -> ForensicEnergyContext = WorkEnergyMonitor.systemContext) {
        self.scheduler = scheduler; self.defaults = defaults; self.sample = sample
        mode = ForensicEnergyMode(rawValue: defaults.string(forKey: "forensicEnergyMode") ?? "") ?? .automatic
        context = sample()
    }

    func start() {
        guard timer == nil else { return }
        // Access thermalState before registering; Foundation requires this to
        // begin receiving thermal-change notifications.
        refresh()
        for name in [ProcessInfo.thermalStateDidChangeNotification, Notification.Name.NSProcessInfoPowerStateDidChange] {
            observers.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor [weak self] in self?.refresh() }
            })
        }
        // The power-state notification concerns Low Power Mode. Periodic public
        // IOKit sampling observes AC/battery transitions about every 30 s, plus scheduling delay.
        let timer = Timer(timeInterval: 30, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in self?.refresh() }
        }
        timer.tolerance = 5
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }

    func stop() {
        timer?.invalidate(); timer = nil
        for observer in observers { NotificationCenter.default.removeObserver(observer) }
        observers.removeAll()
    }

    /// Awaits the latest ordered policy delivery already scheduled by this
    /// monitor. It neither samples the host nor waits for forensic workflows.
    func drainPolicyUpdates() async { await publishTask?.value }

    func selectMode(_ mode: ForensicEnergyMode) {
        guard self.mode != mode else { return }
        self.mode = mode; defaults.set(mode.rawValue, forKey: "forensicEnergyMode")
        refresh()
    }

    func refresh() {
        let next = sample(), changed = next != context
        context = next; sampledAt = Date()
        let selectedMode = mode, previous = publishTask, scheduler = scheduler
        // Preserve sampling order even if actor delivery is temporarily delayed.
        publishTask = Task {
            await previous?.value
            await scheduler.updatePolicy(mode: selectedMode, context: next)
        }
        if changed {
            logger.info("New-work policy power=\(next.powerSource.rawValue, privacy: .public) thermal=\(next.thermalState.rawValue, privacy: .public) lowPower=\(next.lowPowerMode, privacy: .public)")
        }
    }

    static func systemContext() -> ForensicEnergyContext {
        let process = ProcessInfo.processInfo
        let thermal: ForensicThermalState
        switch process.thermalState {
        case .nominal: thermal = .nominal
        case .fair: thermal = .fair
        case .serious: thermal = .serious
        case .critical: thermal = .critical
        @unknown default: thermal = .unknown
        }
        var source: ForensicPowerSource = .unknown
        if let info = IOPSCopyPowerSourcesInfo()?.takeRetainedValue(),
           let type = IOPSGetProvidingPowerSourceType(info)?.takeUnretainedValue() as String? {
            if type == kIOPMACPowerKey { source = .externalPower }
            else if type == kIOPMBatteryPowerKey { source = .battery }
        }
        return .init(powerSource: source, lowPowerMode: process.isLowPowerModeEnabled, thermalState: thermal)
    }
}
