import XCTest
@testable import SmokeSupport

final class ConfigurationTests: XCTestCase {
    func testEndpointRejectsUnsafeInputs() {
        for value in [nil, "", "example.com:8080", "127.0.0.1.evil:8080", "localhost.evil:8080", "http://127.0.0.1:8080", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:no", "user@127.0.0.1:8080"] {
            XCTAssertThrowsError(try Endpoint(value), "accepted unsafe endpoint")
        }
    }
    func testProjectRejectsUnsafeInputs() {
        for value in [nil, "", "real-project", "demo-", "demo-app/other"] {
            XCTAssertThrowsError(try validateProject(value), "accepted unsafe project")
        }
    }
    func testEndpointPreservesLoopbackPort() throws {
        for host in ["127.0.0.1", "localhost"] {
            let endpoint = try Endpoint("\(host):9199")
            XCTAssertEqual(endpoint.host, host)
            XCTAssertEqual(endpoint.port, 9199)
        }
        XCTAssertEqual(try validateProject("demo-app"), "demo-app")
    }
}

extension ConfigurationTests {
    func testGeneratedConfigurationRows() throws {
        guard let path = ProcessInfo.processInfo.environment["SMOKE_PICT_ROWS"] else { return }
        let lines = try String(contentsOfFile: path, encoding: .utf8).split(separator: "\n").dropFirst()
        XCTAssertFalse(lines.isEmpty)
        for line in lines {
            let row = line.split(separator: "\t").map(String.init)
            XCTAssertEqual(row.count, 3)
            let project = row[0] == "valid" ? "demo-app" : "real-project"
            let host = ["loopback": "127.0.0.1", "public": "example.com", "missing": "", "deceptive": "127.0.0.1.example.com"][row[1]]!
            let port = ["valid": "8080", "zero": "0", "overflow": "65536", "malformed": "abc"][row[2]]!
            let expected = row == ["valid", "loopback", "valid"]
            do {
                _ = try validateProject(project)
                _ = try Endpoint(host + ":" + port)
                XCTAssertTrue(expected, "unsafe PICT row accepted")
            } catch { XCTAssertFalse(expected, "safe PICT row rejected") }
        }
    }
    func testDownloadURLRejectsRoutingChanges() throws {
        let endpoint = try Endpoint("127.0.0.1:9199")
        try validateDownloadURL(URL(string: "http://127.0.0.1:9199/file")!, endpoint: endpoint)
        for value in ["https://127.0.0.1:9199/file", "http://example.com:9199/file", "http://127.0.0.1:80/file", "http://user@127.0.0.1:9199/file"] {
            XCTAssertThrowsError(try validateDownloadURL(URL(string: value)!, endpoint: endpoint))
        }
    }
}
