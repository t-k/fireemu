import Foundation

public enum GuardError: Error { case invalidConfiguration }

public struct Endpoint: Equatable, Sendable {
    public let host: String
    public let port: Int
    public init(_ value: String?) throws {
        guard let value else { throw GuardError.invalidConfiguration }
        let pieces = value.split(separator: ":", omittingEmptySubsequences: false)
        guard pieces.count == 2, ["127.0.0.1", "localhost"].contains(String(pieces[0])),
              !pieces[1].isEmpty, pieces[1].allSatisfy({ $0.isASCII && $0.isNumber }),
              let parsed = Int(pieces[1]), (1...65535).contains(parsed)
        else { throw GuardError.invalidConfiguration }
        host = String(pieces[0])
        port = parsed
    }
}

public func validateProject(_ value: String?) throws -> String {
    guard let value, value.hasPrefix("demo-"), value.count > 5,
          value.allSatisfy({ $0.isASCII && ($0.isLowercase || $0.isNumber || $0 == "-") })
    else { throw GuardError.invalidConfiguration }
    return value
}

public func validateDownloadURL(_ url: URL, endpoint: Endpoint) throws {
    guard url.scheme == "http", url.host == endpoint.host, url.port == endpoint.port,
          url.user == nil, url.password == nil else { throw GuardError.invalidConfiguration }
}
