import Foundation
import ForensicsCore
import Testing
@testable import NativeForensics

@Suite("CaseIntegrityWorkspaceTests")
@MainActor
struct CaseIntegrityWorkspaceTests {
    @Test("Audit defaults to historical mode and fresh rehash is an explicit captured choice")
    func requestedMode() async throws {
        let forensicCase = fixtureCase()
        let captured = IntegrityRequestCapture()
        let store = CaseIntegrityWorkspaceStore(audit: { forensicCase, options, _ in
            await captured.record(options.freshEvidenceRehash)
            return Self.report(forensicCase, fresh: options.freshEvidenceRehash)
        }, scheduler: ForensicWorkScheduler())
        store.configure(forensicCase: forensicCase)
        #expect(store.canAudit)
        #expect(!store.freshEvidenceRehash)
        store.runAudit(); await (try #require(store.activeTask)).value
        #expect(store.report?.sourceRehashed == false)
        store.freshEvidenceRehash = true
        store.runAudit(); await (try #require(store.activeTask)).value
        #expect(store.report?.sourceRehashed == true)
        #expect(await captured.values == [false, true])
        #expect(!store.isWorking)
    }

    @Test("A delayed audit from an old case cannot populate the newly configured case")
    func staleCaseResult() async throws {
        let oldCase = fixtureCase(), newCase = fixtureCase()
        let gate = IntegrityReportGate()
        let store = CaseIntegrityWorkspaceStore(audit: { forensicCase, options, _ in
            await gate.hold(Self.report(forensicCase, fresh: options.freshEvidenceRehash))
        }, scheduler: ForensicWorkScheduler())
        store.configure(forensicCase: oldCase); store.runAudit()
        let task = try #require(store.activeTask)
        await gate.waitForOwner()
        store.configure(forensicCase: newCase)
        #expect(store.report == nil)
        #expect(store.isWorking)
        #expect(!store.canAudit)
        await gate.release(); await task.value
        #expect(store.report == nil)
        #expect(!store.isWorking)
        #expect(store.canAudit)
    }

    @Test("Cancel retains the previous report and ownership until the audit owner unwinds")
    func cancellationRetainsReport() async throws {
        let forensicCase = fixtureCase()
        let gate = IntegrityReportGate()
        let captured = IntegrityRequestCapture()
        let store = CaseIntegrityWorkspaceStore(audit: { forensicCase, options, _ in
            await captured.record(options.freshEvidenceRehash)
            let report = Self.report(forensicCase, fresh: options.freshEvidenceRehash)
            if await captured.values.count > 1 { return await gate.hold(report) }
            return report
        }, scheduler: ForensicWorkScheduler())
        store.configure(forensicCase: forensicCase); store.runAudit()
        await (try #require(store.activeTask)).value
        let earlier = try #require(store.report)
        store.freshEvidenceRehash = true; store.runAudit()
        let task = try #require(store.activeTask)
        await gate.waitForOwner(); store.cancelPendingWork()
        #expect(store.isWorking)
        #expect(store.report == earlier)
        await gate.release(); await task.value
        #expect(store.report == earlier)
        #expect(!store.isWorking)
        #expect(store.statusMessage.contains("cancelled"))
    }

    @Test("Shutdown cancels and drains audit ownership and prevents subsequent requests")
    func shutdownDrainsOwner() async throws {
        let forensicCase = fixtureCase(), gate = IntegrityReportGate()
        let store = CaseIntegrityWorkspaceStore(audit: { forensicCase, options, _ in
            await gate.hold(Self.report(forensicCase, fresh: options.freshEvidenceRehash))
        }, scheduler: ForensicWorkScheduler())
        store.configure(forensicCase: forensicCase); store.runAudit()
        await gate.waitForOwner()
        let shutdown = try #require(store.beginShutdown())
        #expect(store.isClosing)
        #expect(store.isWorking)
        #expect(!store.canAudit)
        store.configure(forensicCase: fixtureCase()); store.runAudit()
        await gate.release(); await shutdown.value
        #expect(!store.isWorking)
        #expect(store.report == nil)
    }

    @Test("A chooser completing after a case switch cannot export an old report into the new case")
    func staleExportChooser() async throws {
        let forensicCase = fixtureCase(), chooser = IntegrityDestinationGate(), capture = IntegrityRequestCapture()
        let store = CaseIntegrityWorkspaceStore(audit: { forensicCase, options, _ in Self.report(forensicCase, fresh: options.freshEvidenceRehash) },
            chooseDestination: { _ in await chooser.hold() }, export: { _, _, _, destination, privatePaths in
                await capture.record(privatePaths); return destination
            }, scheduler: ForensicWorkScheduler())
        store.configure(forensicCase: forensicCase); store.runAudit()
        await (try #require(store.activeTask)).value
        store.exportReport(format: .json)
        let task = try #require(store.activeTask)
        await chooser.waitForOwner(); store.configure(forensicCase: fixtureCase())
        await chooser.release(URL(fileURLWithPath: "/synthetic/new-report.json")); await task.value
        #expect(await capture.values.isEmpty)
        #expect(store.reportURL == nil)
        #expect(!store.isWorking)
    }

    @Test("Host path retention defaults off and is captured when an export begins")
    func exportPathChoice() async throws {
        let forensicCase = fixtureCase(), capture = IntegrityRequestCapture()
        let destination = URL(fileURLWithPath: "/synthetic/new-report.md")
        let store = CaseIntegrityWorkspaceStore(audit: { forensicCase, options, _ in Self.report(forensicCase, fresh: options.freshEvidenceRehash) },
            chooseDestination: { _ in destination }, export: { _, _, _, output, privatePaths in
                await capture.record(privatePaths); return output
            }, scheduler: ForensicWorkScheduler())
        store.configure(forensicCase: forensicCase); store.runAudit()
        await (try #require(store.activeTask)).value
        #expect(!store.includePrivatePaths)
        store.exportReport(format: .markdown); await (try #require(store.activeTask)).value
        #expect(store.reportURL == destination)
        store.includePrivatePaths = true
        store.exportReport(format: .json); await (try #require(store.activeTask)).value
        #expect(await capture.values == [false, true])
        #expect(!store.isWorking)
    }

    @Test("A foreign report receipt is rejected before display or export")
    func foreignReceipt() async throws {
        let store = CaseIntegrityWorkspaceStore(audit: { _, options, _ in Self.report(Self.makeCase(), fresh: options.freshEvidenceRehash) },
            scheduler: ForensicWorkScheduler())
        store.configure(forensicCase: fixtureCase()); store.runAudit()
        await (try #require(store.activeTask)).value
        #expect(store.report == nil)
        #expect(store.errorMessage != nil)
        #expect(!store.canExport)
    }

    private func fixtureCase() -> ForensicCase { Self.makeCase() }
    private nonisolated static func makeCase() -> ForensicCase {
        ForensicCase(bundleURL: URL(fileURLWithPath: "/synthetic/\(UUID().uuidString).nativecase"), manifest: CaseManifest(name: "Synthetic Case"))
    }
    private nonisolated static func report(_ forensicCase: ForensicCase, fresh: Bool) -> CaseIntegrityReport {
        CaseIntegrityReport(caseID: forensicCase.manifest.id, casePath: forensicCase.bundleURL.path,
            manifestSHA256: nil, sourceRehashed: fresh, isPartial: false,
            checks: [.init(status: .pass, code: "manifest.valid", relativePath: "manifest.json", message: "Synthetic test receipt")])
    }
}

private actor IntegrityRequestCapture {
    private(set) var values: [Bool] = []
    func record(_ value: Bool) { values.append(value) }
}

private actor IntegrityReportGate {
    private var continuation: CheckedContinuation<CaseIntegrityReport, Never>?
    private var report: CaseIntegrityReport?
    private var waiter: CheckedContinuation<Void, Never>?
    func hold(_ value: CaseIntegrityReport) async -> CaseIntegrityReport {
        report = value
        return await withCheckedContinuation { continuation in
            self.continuation = continuation; waiter?.resume(); waiter = nil
        }
    }
    func waitForOwner() async {
        if continuation != nil { return }
        await withCheckedContinuation { waiter = $0 }
    }
    func release() {
        if let report { continuation?.resume(returning: report) }; continuation = nil
    }
}

private actor IntegrityDestinationGate {
    private var continuation: CheckedContinuation<URL?, Never>?
    private var waiter: CheckedContinuation<Void, Never>?
    func hold() async -> URL? {
        await withCheckedContinuation { continuation in self.continuation = continuation; waiter?.resume(); waiter = nil }
    }
    func waitForOwner() async {
        if continuation != nil { return }
        await withCheckedContinuation { waiter = $0 }
    }
    func release(_ value: URL?) { continuation?.resume(returning: value); continuation = nil }
}
