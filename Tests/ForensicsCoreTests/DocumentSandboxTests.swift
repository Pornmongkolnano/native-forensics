import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ForensicsCore

/// These probes exercise actual macOS enforcement with the production policy.
/// No external address, DNS lookup, credentials, or coursework file is used.
struct DocumentSandboxTests {
    @Test func publicClientRequiresSandboxAndMissingLauncherFailsClosed() throws {
        let helper = URL(fileURLWithPath: "/usr/bin/true")
        let input = URL(fileURLWithPath: "/private/tmp/synthetic-document.txt")
        #expect(DocumentAnalysisClient(helperURL: helper).sandboxPolicy == .required)
        #expect(throws: DocumentAnalysisError.sandboxUnavailable) {
            try DocumentSandbox.launch(helper: helper, input: input, policy: .required,
                launcher: URL(fileURLWithPath: "/private/tmp/missing-nf-sandbox-\(UUID().uuidString)"))
        }
        #expect(throws: DocumentAnalysisError.sandboxUnavailable) {
            try DocumentSandbox.launch(helper: helper, input: input, policy: .required,
                launcher: URL(fileURLWithPath: "/usr/bin", isDirectory: true))
        }
    }

    @Test func requiredPolicyAllowsOnlyInputDataAndDeniesWritesNetworkAndOtherExecutables() async throws {
        let fixture = try SandboxProbeFixture()
        defer { fixture.remove() }
        let result = try await DocumentAnalysisClient(helperURL: fixture.helper).analyze(fixture.input)
        #expect(result.textPages.first?.text == "input-read=1 outside-read-denied=1 source-write-denied=1 create-denied=1 ipv4-outbound-denied=1 ipv4-bind-denied=1 unix-socket-denied=1 other-exec-denied=1")
        #expect(try Data(contentsOf: fixture.source) == fixture.sourceBytes)
        #expect(try Data(contentsOf: fixture.outside) == fixture.outsideBytes)
        #expect(!FileManager.default.fileExists(atPath: fixture.newFile.path))
        #expect(!FileManager.default.fileExists(atPath: fixture.socketPath.path))
    }
}

private struct SandboxProbeFixture {
    let root: URL, source: URL, outside: URL, newFile: URL, socketPath: URL, helper: URL
    let input: DocumentInput
    let sourceBytes = Data("Synthetic sandbox receipt 😀".utf8)
    let outsideBytes = Data("A different private file must be unreadable".utf8)

    init() throws {
        // Keep the Unix-socket name within sockaddr_un's independent size cap.
        root = URL(fileURLWithPath: "/private/tmp/nf-document-sandbox-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        source = root.appendingPathComponent("input \" ) (allow default) ; ñ.txt")
        outside = root.appendingPathComponent("outside.txt")
        newFile = root.appendingPathComponent("must-not-exist")
        socketPath = root.appendingPathComponent("socket")
        helper = root.appendingPathComponent("probe")
        input = DocumentInput(fileURL: source, expectedSHA256: SHA256.hash(data: sourceBytes).map { String(format: "%02x", $0) }.joined(), expectedByteCount: Int64(sourceBytes.count))
        do {
            try sourceBytes.write(to: source)
            try outsideBytes.write(to: outside)
            let response = DocumentAnalysis(contentKind: .text, mimeType: "text/plain", status: .decoded,
                sourceSHA256: input.expectedSHA256, sourceByteCount: input.expectedByteCount,
                textPages: [DocumentTextPage(pageNumber: 1, text: "REPLACED_BY_PROBE")])
            let responseJSON = String(decoding: try JSONEncoder().encode(response), as: UTF8.self)
            func cString(_ value: String) throws -> String {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.withoutEscapingSlashes]
                return String(decoding: try encoder.encode(value), as: UTF8.self)
            }
            // The C probe is independent of the decoder implementation. It
            // attempts real forbidden syscalls, then emits a receipt-bound
            // response through its inherited stdout pipe. connect() targets
            // only loopback port zero; bind() uses an ephemeral local port.
            let code = """
            #include <arpa/inet.h>
            #include <errno.h>
            #include <fcntl.h>
            #include <spawn.h>
            #include <stdio.h>
            #include <string.h>
            #include <sys/socket.h>
            #include <sys/un.h>
            #include <sys/wait.h>
            #include <unistd.h>
            extern char **environ;
            static int denied(int result) { return result == -1 && (errno == EPERM || errno == EACCES); }
            static int file_denied(const char *path, int flags) {
                int fd = open(path, flags, 0600); int answer = denied(fd);
                if (fd >= 0) close(fd); return answer;
            }
            static int ipv4_denied(int incoming) {
                int fd = socket(AF_INET, SOCK_STREAM, 0);
                if (fd < 0) return denied(fd);
                struct sockaddr_in address = {0}; address.sin_len = sizeof(address);
                address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                address.sin_port = 0;
                int result = incoming ? bind(fd, (struct sockaddr *)&address, sizeof(address))
                    : connect(fd, (struct sockaddr *)&address, sizeof(address));
                int answer = denied(result); close(fd); return answer;
            }
            static int unix_denied(void) {
                int fd = socket(AF_UNIX, SOCK_STREAM, 0); if (fd < 0) return denied(fd);
                struct sockaddr_un address = {0}; address.sun_len = sizeof(address); address.sun_family = AF_UNIX;
                snprintf(address.sun_path, sizeof(address.sun_path), "%s", \(try cString(socketPath.path)));
                int result = bind(fd, (struct sockaddr *)&address, sizeof(address));
                int answer = denied(result); close(fd); return answer;
            }
            int main(void) {
                char buffer[4096]; while (read(STDIN_FILENO, buffer, sizeof(buffer)) > 0) {}
                int input = open(\(try cString(source.path)), O_RDONLY);
                int readable = input >= 0 && read(input, buffer, sizeof(buffer)) > 0;
                if (input >= 0) close(input);
                int outside = file_denied(\(try cString(outside.path)), O_RDONLY);
                int write = file_denied(\(try cString(source.path)), O_WRONLY);
                int create = file_denied(\(try cString(newFile.path)), O_WRONLY | O_CREAT | O_EXCL);
                int outbound = ipv4_denied(0), incoming = ipv4_denied(1), local = unix_denied();
                pid_t child = 0; char *arguments[] = {"/usr/bin/true", NULL};
                int spawn = posix_spawn(&child, arguments[0], NULL, NULL, arguments, environ);
                int execDenied = spawn == EPERM || spawn == EACCES;
                if (spawn == 0) { int status; while (waitpid(child, &status, 0) < 0 && errno == EINTR) {} }
                char flags[512]; snprintf(flags, sizeof(flags),
                    "input-read=%d outside-read-denied=%d source-write-denied=%d create-denied=%d ipv4-outbound-denied=%d ipv4-bind-denied=%d unix-socket-denied=%d other-exec-denied=%d",
                    readable, outside, write, create, outbound, incoming, local, execDenied);
                const char *response = \(try cString(responseJSON));
                const char *marker = strstr(response, "REPLACED_BY_PROBE"); if (!marker) return 2;
                fwrite(response, 1, (size_t)(marker - response), stdout); fputs(flags, stdout);
                fputs(marker + strlen("REPLACED_BY_PROBE"), stdout); fputc('\\n', stdout); return 0;
            }
            """
            let sourceCode = root.appendingPathComponent("probe.c")
            try Data(code.utf8).write(to: sourceCode)
            let compiler = Process()
            compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
            compiler.arguments = ["clang", "-Wall", "-Wextra", "-Werror", sourceCode.path, "-o", helper.path]
            let errors = Pipe()
            compiler.standardOutput = errors; compiler.standardError = errors
            try compiler.run()
            let diagnostics = errors.fileHandleForReading.readDataToEndOfFile()
            compiler.waitUntilExit()
            guard compiler.terminationStatus == 0 else {
                Issue.record("Synthetic sandbox probe compilation failed: \(String(decoding: diagnostics.prefix(8_192), as: UTF8.self))")
                throw DocumentAnalysisError.launchFailed
            }
        } catch {
            try? FileManager.default.removeItem(at: root)
            throw error
        }
    }

    func remove() { try? FileManager.default.removeItem(at: root) }
}
