import Foundation

/// Syntax is selected explicitly; query text is never an FTS or regex program.
public enum ContentIndexSearchMode: String, Sendable, Equatable, Hashable, CaseIterable {
    case literal, phrase, tokenPrefix
}

public struct ContentIndexQueryRequest: Sendable, Equatable {
    public let query: String
    public let mode: ContentIndexSearchMode
    public let caseSensitive: Bool

    public init(query: String, mode: ContentIndexSearchMode = .literal, caseSensitive: Bool = false) {
        self.query = query; self.mode = mode; self.caseSensitive = caseSensitive
    }
    public static func == (left: Self, right: Self) -> Bool {
        left.mode == right.mode && left.caseSensitive == right.caseSensitive
            && left.query.utf8.elementsEqual(right.query.utf8)
    }
}

/// Foundation word enumeration with explicit Thai-language refinement, in the
/// original query without normalization.
/// A token is a platform word boundary, not a guarantee of linguistic meaning.
public struct ContentIndexQueryToken: Sendable, Equatable {
    public let text: String
    public let utf16Offset: Int
    public let utf16Length: Int
    public static func == (left: Self, right: Self) -> Bool {
        left.utf16Offset == right.utf16Offset && left.utf16Length == right.utf16Length
            && left.text.utf8.elementsEqual(right.text.utf8)
    }
}

public enum ContentIndexQueryIssue: String, Sendable, Equatable {
    case emptyQuery, queryTooLong, noWordTokens, phraseContainsNonWordText, prefixRequiresSingleToken
}

/// Keeps query semantics with the immutable source/generation reference. The
/// original reference remains compatible with recorded-file navigation.
public struct ContentIndexQueryReference: Sendable, Equatable {
    public let caseID: UUID
    public let request: ContentIndexQueryRequest
    public let indexReference: ContentIndexReference
}

public struct CaseContentQueryHit: Sendable, Equatable, Identifiable {
    public let id: Int
    public let reference: ContentIndexQueryReference
    public let snippet: String
}

public struct CaseContentQueryOutcome: Sendable, Equatable {
    public let request: ContentIndexQueryRequest
    public let queryTokens: [ContentIndexQueryToken]
    public let queryIssue: ContentIndexQueryIssue?
    public let hits: [CaseContentQueryHit]
    public let hitLimitReached: Bool
    public let coverageIsPartial: Bool
    public var query: String { request.query }
    public var mode: ContentIndexSearchMode { request.mode }
}
