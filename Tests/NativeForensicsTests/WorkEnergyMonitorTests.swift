import Foundation
import Testing
@testable import ForensicsCore
@testable import NativeForensics

@Suite("WorkEnergyMonitorTests")
@MainActor
struct WorkEnergyMonitorTests {
    @Test("Explicit energy choice persists in an isolated preference domain and updates admission")
    func explicitChoicePersistence() async throws {
        let name = "NativeForensics.EnergyTest." + UUID().uuidString
        let defaults = try #require(UserDefaults(suiteName: name))
        defer { defaults.removePersistentDomain(forName: name) }
        let scheduler = ForensicWorkScheduler(), sample = EnergySampleBox()
        let monitor = WorkEnergyMonitor(scheduler: scheduler, defaults: defaults, sample: { sample.value })
        #expect(monitor.mode == .automatic && monitor.nextPolicy.priority == .userInitiated)
        monitor.selectMode(.conserveEnergy)
        await monitor.drainPolicyUpdates()
        #expect(await scheduler.state().nextPolicy.mode == .conserveEnergy)
        #expect(await scheduler.state().nextPolicy.priority == .utility)
        let reopened = WorkEnergyMonitor(scheduler: scheduler, defaults: defaults, sample: { sample.value })
        #expect(reopened.mode == .conserveEnergy)
        #expect(reopened.nextPolicy.reasons == [.explicitConservation])
        monitor.selectMode(.automatic)
        await monitor.drainPolicyUpdates()
        #expect(defaults.string(forKey: "forensicEnergyMode") == "automatic")
        #expect(await scheduler.state().nextPolicy.priority == .userInitiated)
    }

    @Test("Rapid injected samples deliver in order and leave the active policy frozen")
    func orderedRefreshPreservesActiveOwner() async throws {
        let name = "NativeForensics.EnergyTest." + UUID().uuidString
        let defaults = try #require(UserDefaults(suiteName: name))
        defer { defaults.removePersistentDomain(forName: name) }
        let scheduler = ForensicWorkScheduler(), sample = EnergySampleBox()
        let monitor = WorkEnergyMonitor(scheduler: scheduler, defaults: defaults, sample: { sample.value })
        monitor.refresh(); await monitor.drainPolicyUpdates()
        let owner = try await scheduler.acquireImmediately(.recovery)
        #expect(owner.admission.policy.priority == .userInitiated)
        sample.value = .init(powerSource: .battery, lowPowerMode: true, thermalState: .fair)
        monitor.refresh()
        sample.value = .init(powerSource: .unknown, lowPowerMode: false, thermalState: .serious)
        monitor.refresh()
        monitor.selectMode(.conserveEnergy)
        sample.value = .init(powerSource: .externalPower, lowPowerMode: false, thermalState: .nominal)
        monitor.refresh()
        await monitor.drainPolicyUpdates()
        let state = await scheduler.state()
        #expect(state.active == owner.admission)
        #expect(state.active?.policy.priority == .userInitiated)
        #expect(state.nextPolicy.context == sample.value)
        #expect(state.nextPolicy.mode == .conserveEnergy)
        #expect(state.nextPolicy.reasons == [.explicitConservation])
        #expect(monitor.context == sample.value && monitor.sampledAt != nil)
        #expect(await owner.release())
        let next = try await scheduler.acquireImmediately(.recovery)
        #expect(next.admission.policy.priority == .utility)
        #expect(next.admission.policy.context == sample.value)
        #expect(await next.release())
    }
}

@MainActor
private final class EnergySampleBox {
    var value = ForensicEnergyContext(powerSource: .externalPower, lowPowerMode: false, thermalState: .nominal)
}
