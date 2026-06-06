import AppKit
import Combine
import CryptoKit
import Foundation
import SQLite3
import SwiftUI

private let appName = "O-Clip"
private let selfWriteType = NSPasteboard.PasteboardType("com.boninall.oclip.self-write")
private let sqliteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
private let jsonDecoder = JSONDecoder()
private let jsonEncoder = JSONEncoder()

struct RustImageInfo: Codable {
    let width: Int
    let height: Int
    let bitsPerPixel: Int
    let dataSize: Int
    let format: String
    let rawData: String?

    enum CodingKeys: String, CodingKey {
        case width
        case height
        case bitsPerPixel = "bits_per_pixel"
        case dataSize = "data_size"
        case format
        case rawData = "raw_data"
    }
}

struct FileRef: Codable {
    let fileId: String
    let filename: String
    let size: Int64
    let mimeType: String

    enum CodingKeys: String, CodingKey {
        case fileId = "file_id"
        case filename
        case size
        case mimeType = "mime_type"
    }
}

struct ImageRef: Codable {
    let imageId: String
    let width: Int
    let height: Int
    let bitsPerPixel: Int
    let format: String
    let size: Int64

    enum CodingKeys: String, CodingKey {
        case imageId = "image_id"
        case width
        case height
        case bitsPerPixel = "bits_per_pixel"
        case format
        case size
    }
}

enum RustClipboardContent: Codable {
    case text(String)
    case url(String)
    case files([String])
    case syncedFiles([FileRef])
    case image(RustImageInfo)
    case syncedImage(ImageRef)

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let object = try container.decode([String: Payload].self)
        if let value = object["Text"]?.string {
            self = .text(value)
        } else if let value = object["Url"]?.string {
            self = .url(value)
        } else if let value = object["Files"]?.strings {
            self = .files(value)
        } else if let value = object["SyncedFiles"]?.fileRefs {
            self = .syncedFiles(value)
        } else if let value = object["Image"]?.image {
            self = .image(value)
        } else if let value = object["SyncedImage"]?.imageRef {
            self = .syncedImage(value)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported clipboard content")
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .text(let value):
            try container.encode(["Text": Payload.string(value)])
        case .url(let value):
            try container.encode(["Url": Payload.string(value)])
        case .files(let value):
            try container.encode(["Files": Payload.strings(value)])
        case .syncedFiles(let value):
            try container.encode(["SyncedFiles": Payload.fileRefs(value)])
        case .image(let value):
            try container.encode(["Image": Payload.image(value)])
        case .syncedImage(let value):
            try container.encode(["SyncedImage": Payload.imageRef(value)])
        }
    }

    enum Payload: Codable {
        case string(String)
        case strings([String])
        case fileRefs([FileRef])
        case image(RustImageInfo)
        case imageRef(ImageRef)

        var string: String? {
            if case .string(let value) = self { return value }
            return nil
        }

        var strings: [String]? {
            if case .strings(let value) = self { return value }
            return nil
        }

        var fileRefs: [FileRef]? {
            if case .fileRefs(let value) = self { return value }
            return nil
        }

        var image: RustImageInfo? {
            if case .image(let value) = self { return value }
            return nil
        }

        var imageRef: ImageRef? {
            if case .imageRef(let value) = self { return value }
            return nil
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let value = try? container.decode(String.self) {
                self = .string(value)
            } else if let value = try? container.decode([String].self) {
                self = .strings(value)
            } else if let value = try? container.decode([FileRef].self) {
                self = .fileRefs(value)
            } else {
                do {
                    self = .image(try container.decode(RustImageInfo.self))
                } catch {
                    self = .imageRef(try container.decode(ImageRef.self))
                }
            }
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .string(let value):
                try container.encode(value)
            case .strings(let value):
                try container.encode(value)
            case .fileRefs(let value):
                try container.encode(value)
            case .image(let value):
                try container.encode(value)
            case .imageRef(let value):
                try container.encode(value)
            }
        }
    }
}

extension RustClipboardContent {
    var contentType: String {
        switch self {
        case .text: return "text"
        case .url: return "url"
        case .files, .syncedFiles: return "files"
        case .image, .syncedImage: return "image"
        }
    }

    var contentJSON: String {
        guard let data = try? jsonEncoder.encode(self) else { return "{}" }
        return String(data: data, encoding: .utf8) ?? "{}"
    }

    var byteSize: Int {
        switch self {
        case .text(let text): return text.utf8.count
        case .url(let url): return url.utf8.count
        case .files(let paths): return paths.reduce(0) { $0 + $1.utf8.count }
        case .syncedFiles(let refs): return refs.reduce(0) { $0 + Int($1.size) }
        case .image(let image): return image.dataSize
        case .syncedImage(let image): return Int(image.size)
        }
    }

    func preview(maxLength: Int = 120) -> String {
        switch self {
        case .text(let text):
            return clipped(text.components(separatedBy: .newlines).first ?? text, maxLength: maxLength)
        case .url(let url):
            return clipped(url, maxLength: maxLength)
        case .files(let paths):
            if paths.count == 1 {
                let url = URL(fileURLWithPath: paths[0])
                return url.lastPathComponent.isEmpty ? paths[0] : url.lastPathComponent
            }
            return "\(paths.count) files"
        case .syncedFiles(let refs):
            if refs.count == 1 {
                return refs[0].filename
            }
            return "\(refs.count) files"
        case .image(let image):
            return "\(image.width)x\(image.height) \(image.format)"
        case .syncedImage(let image):
            return "\(image.width)x\(image.height) \(image.format)"
        }
    }

    var contentHash: String {
        var data = Data()
        switch self {
        case .text(let text):
            data.appendString("text:")
            data.appendString(text)
        case .url(let url):
            data.appendString("url:")
            data.appendString(url)
        case .files(let paths):
            data.appendString("files:")
            for path in paths.sorted() {
                data.appendString(path)
                data.append(0)
            }
        case .syncedFiles(let refs):
            data.appendString("files:")
            for fileId in refs.map(\.fileId).sorted() {
                data.appendString(fileId)
                data.append(0)
            }
        case .image(let image):
            data.appendString("image:")
            data.appendUInt32LE(UInt32(image.width))
            data.appendUInt32LE(UInt32(image.height))
            if let rgba = rgbaBytes(from: image) {
                data.append(rgba)
            } else if let raw = image.rawData {
                data.appendString(raw)
            } else {
                data.appendUInt32LE(UInt32(image.bitsPerPixel))
                data.appendUInt32LE(UInt32(image.dataSize))
            }
        case .syncedImage(let image):
            data.appendString("image:")
            data.appendString(image.imageId)
        }
        return sha256Hex(data)
    }

    var isRestorableAfterExternalPlaceholder: Bool {
        switch self {
        case .files, .syncedFiles, .image, .syncedImage:
            return true
        case .text, .url:
            return false
        }
    }

    var debugSummary: String {
        let hash = shortHash(contentHash)
        switch self {
        case .text(let text):
            return "type=text bytes=\(byteSize) chars=\(text.count) hash=\(hash)"
        case .url(let url):
            return "type=url bytes=\(byteSize) chars=\(url.count) hash=\(hash)"
        case .files(let paths):
            return "type=files count=\(paths.count) bytes=\(byteSize) hash=\(hash) paths=[\(debugFilePaths(paths))]"
        case .syncedFiles(let refs):
            return "type=syncedFiles count=\(refs.count) bytes=\(byteSize) hash=\(hash) refs=[\(debugFileRefs(refs))]"
        case .image(let image):
            return "type=image hash=\(hash) \(image.debugSummary)"
        case .syncedImage(let image):
            return "type=syncedImage hash=\(hash) \(image.debugSummary)"
        }
    }
}

extension RustImageInfo {
    var debugSummary: String {
        "size=\(dataSize) \(width)x\(height) bpp=\(bitsPerPixel) format=\(format) raw=\(rawData == nil ? "nil" : "base64")"
    }
}

extension ImageRef {
    var debugSummary: String {
        "id=\(shortHash(imageId)) size=\(size) \(width)x\(height) bpp=\(bitsPerPixel) format=\(format)"
    }
}

extension FileRef {
    var debugSummary: String {
        "\(filename)(id=\(shortHash(fileId)),size=\(size),mime=\(mimeType))"
    }
}

private func oclipLog(_ message: String) {
    NSLog("o-clip \(message)")
}

private func shortHash(_ value: String) -> String {
    String(value.prefix(16))
}

private func debugFileRefs(_ refs: [FileRef]) -> String {
    refs.map(\.debugSummary).joined(separator: ", ")
}

private func debugFilePaths(_ paths: [String]) -> String {
    paths.map { path in
        let url = URL(fileURLWithPath: path)
        let attrs = try? FileManager.default.attributesOfItem(atPath: path)
        let size = (attrs?[.size] as? NSNumber)?.int64Value
        let exists = FileManager.default.fileExists(atPath: path)
        return "\(url.lastPathComponent)(exists=\(exists),size=\(size.map(String.init) ?? "nil"))"
    }.joined(separator: ", ")
}

private func clipped(_ value: String, maxLength: Int) -> String {
    if value.count <= maxLength { return value }
    let index = value.index(value.startIndex, offsetBy: maxLength)
    return String(value[..<index]) + "..."
}

private func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

struct AppConfig {
    var maxEntries: Int = 10_000
    var dbPath: String = ""
    var serverURL: String = ""
    var autoConnect: Bool = true
    var maxSyncSize: Int = 5 * 1024 * 1024
    var acceptInvalidCerts: Bool = false
    var password: String?
    var maxFileSyncSize: Int = 50 * 1024 * 1024
    var downloadDir: String = ""
    var imageInlineThreshold: Int = 200 * 1024

    static var supportDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent("o-clip", isDirectory: true)
    }

    static var configURL: URL {
        supportDirectory.appendingPathComponent("config.toml")
    }

    var databaseURL: URL {
        if !dbPath.isEmpty {
            return URL(fileURLWithPath: AppConfig.expandingTilde(dbPath))
        }
        return AppConfig.supportDirectory.appendingPathComponent("clipboard.db")
    }

    static func load() -> AppConfig {
        let url = configURL
        if !FileManager.default.fileExists(atPath: url.path) {
            writeDefault(to: url)
            return AppConfig()
        }

        guard let text = try? String(contentsOf: url, encoding: .utf8) else {
            return AppConfig()
        }

        var config = AppConfig()
        var section = ""
        for rawLine in text.components(separatedBy: .newlines) {
            let line = stripTomlComment(rawLine)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty { continue }
            if line.hasPrefix("["), line.hasSuffix("]") {
                section = String(line.dropFirst().dropLast()).trimmingCharacters(in: .whitespacesAndNewlines)
                continue
            }

            let parts = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }
            let key = parts[0].trimmingCharacters(in: .whitespacesAndNewlines)
            let value = parseTomlValue(String(parts[1]))

            if section == "storage", key == "max_entries", let intValue = Int(value) {
                config.maxEntries = intValue
            } else if section == "storage", key == "db_path" {
                config.dbPath = value
            } else if section == "server", key == "url" {
                config.serverURL = value
            } else if section == "server", key == "auto_connect" {
                config.autoConnect = parseBool(value, defaultValue: true)
            } else if section == "server", key == "max_sync_size", let intValue = Int(value) {
                config.maxSyncSize = intValue
            } else if section == "server", key == "accept_invalid_certs" {
                config.acceptInvalidCerts = parseBool(value, defaultValue: false)
            } else if section == "server", key == "password" {
                config.password = value.isEmpty ? nil : value
            } else if section == "server", key == "max_file_sync_size", let intValue = Int(value) {
                config.maxFileSyncSize = intValue
            } else if section == "server", key == "download_dir" {
                config.downloadDir = value
            } else if section == "server", key == "image_inline_threshold", let intValue = Int(value) {
                config.imageInlineThreshold = intValue
            }
        }
        return config
    }

    private static func writeDefault(to url: URL) {
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let body = AppConfig().tomlString()
        try? body.write(to: url, atomically: true, encoding: .utf8)
    }

    func write(to url: URL = AppConfig.configURL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try tomlString().write(to: url, atomically: true, encoding: .utf8)
    }

    private func tomlString() -> String {
        """
        [server]
        url = "\(AppConfig.tomlEscaped(serverURL))"
        auto_connect = \(autoConnect ? "true" : "false")
        max_sync_size = \(maxSyncSize)
        accept_invalid_certs = \(acceptInvalidCerts ? "true" : "false")
        password = "\(AppConfig.tomlEscaped(password ?? ""))"
        max_file_sync_size = \(maxFileSyncSize)
        download_dir = "\(AppConfig.tomlEscaped(downloadDir))"
        image_inline_threshold = \(imageInlineThreshold)

        [storage]
        max_entries = \(maxEntries)
        db_path = "\(AppConfig.tomlEscaped(dbPath))"
        """
    }

    private static func tomlEscaped(_ value: String) -> String {
        value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
    }

    private static func parseTomlValue(_ value: String) -> String {
        var result = stripTomlComment(value).trimmingCharacters(in: .whitespacesAndNewlines)
        if result.hasPrefix("\""), result.hasSuffix("\""), result.count >= 2 {
            result = String(result.dropFirst().dropLast())
                .replacingOccurrences(of: "\\\"", with: "\"")
                .replacingOccurrences(of: "\\n", with: "\n")
                .replacingOccurrences(of: "\\\\", with: "\\")
        }
        return result
    }

    private static func stripTomlComment(_ value: String) -> String {
        var inString = false
        var escaped = false

        for index in value.indices {
            let character = value[index]
            if inString, escaped {
                escaped = false
                continue
            }
            if inString, character == "\\" {
                escaped = true
                continue
            }
            if character == "\"" {
                inString.toggle()
                continue
            }
            if character == "#", !inString {
                return String(value[..<index])
            }
        }

        return value
    }

    private static func expandingTilde(_ path: String) -> String {
        if path == "~" {
            return NSHomeDirectory()
        }
        if path.hasPrefix("~/") {
            return NSHomeDirectory() + String(path.dropFirst())
        }
        return path
    }

    var resolvedDownloadDirectory: URL {
        if !downloadDir.isEmpty {
            return URL(fileURLWithPath: AppConfig.expandingTilde(downloadDir))
        }
        let downloads = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
        return (downloads ?? AppConfig.supportDirectory).appendingPathComponent("o-clip", isDirectory: true)
    }

    private static func parseBool(_ value: String, defaultValue: Bool) -> Bool {
        switch value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "true", "1", "yes", "on": return true
        case "false", "0", "no", "off": return false
        default: return defaultValue
        }
    }
}

struct ClipboardEntry {
    let id: Int64
    let contentType: String
    let content: String
    let preview: String
    let hash: String
    let byteSize: Int64
    let synced: Bool
    let createdAt: String
    let source: String
    let pinned: Bool
}

final class ClipboardStore {
    private var db: OpaquePointer?

    init(path: URL) throws {
        try FileManager.default.createDirectory(at: path.deletingLastPathComponent(), withIntermediateDirectories: true)
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        guard sqlite3_open_v2(path.path, &db, flags, nil) == SQLITE_OK else {
            throw StoreError.open(message: lastError)
        }
        try execute("PRAGMA journal_mode=WAL;")
        try migrate()
    }

    deinit {
        sqlite3_close(db)
    }

    func list(query: String) throws -> [ClipboardEntry] {
        if query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return try rows(
                sql: """
                SELECT id, content_type, content, preview, hash, byte_size, synced, created_at, source, pinned
                FROM entries ORDER BY pinned DESC, created_at DESC LIMIT 300
                """,
                bindings: []
            )
        }
        return try rows(
            sql: """
            SELECT id, content_type, content, preview, hash, byte_size, synced, created_at, source, pinned
            FROM entries WHERE preview LIKE ?1 OR content LIKE ?1
            ORDER BY pinned DESC, created_at DESC LIMIT 300
            """,
            bindings: ["%\(query)%"]
        )
    }

    func insert(_ captured: CapturedClipboard, maxEntries: Int, synced: Bool) throws {
        let now = ISO8601DateFormatter.oclip.string(from: Date())
        try statement(
            sql: """
            INSERT INTO entries (content_type, content, preview, hash, byte_size, synced, created_at, source)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(hash) DO UPDATE SET created_at = excluded.created_at, source = excluded.source
            """
        ) { stmt in
            bind(captured.contentType, to: stmt, index: 1)
            bind(captured.contentJSON, to: stmt, index: 2)
            bind(captured.preview, to: stmt, index: 3)
            bind(captured.hash, to: stmt, index: 4)
            sqlite3_bind_int64(stmt, 5, Int64(captured.byteSize))
            sqlite3_bind_int(stmt, 6, synced ? 1 : 0)
            bind(now, to: stmt, index: 7)
            bind("local", to: stmt, index: 8)
            guard sqlite3_step(stmt) == SQLITE_DONE else {
                throw StoreError.query(message: lastError)
            }
        }
        try enforceLimit(maxEntries)
    }

    func insert(_ entry: ClipboardEntry, maxEntries: Int) throws {
        try statement(
            sql: """
            INSERT INTO entries (content_type, content, preview, hash, byte_size, synced, created_at, source)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(hash) DO UPDATE SET
                content = excluded.content,
                preview = excluded.preview,
                byte_size = excluded.byte_size,
                synced = excluded.synced,
                created_at = excluded.created_at,
                source = excluded.source
            """
        ) { stmt in
            bind(entry.contentType, to: stmt, index: 1)
            bind(entry.content, to: stmt, index: 2)
            bind(entry.preview, to: stmt, index: 3)
            bind(entry.hash, to: stmt, index: 4)
            sqlite3_bind_int64(stmt, 5, entry.byteSize)
            sqlite3_bind_int(stmt, 6, entry.synced ? 1 : 0)
            bind(entry.createdAt, to: stmt, index: 7)
            bind(entry.source, to: stmt, index: 8)
            guard sqlite3_step(stmt) == SQLITE_DONE else {
                throw StoreError.query(message: lastError)
            }
        }
        try enforceLimit(maxEntries)
    }

    func hasHash(_ hash: String) throws -> Bool {
        try statement(sql: "SELECT 1 FROM entries WHERE hash = ?1 LIMIT 1") { stmt in
            bind(hash, to: stmt, index: 1)
            return sqlite3_step(stmt) == SQLITE_ROW
        }
    }

    func delete(id: Int64) throws {
        try statement(sql: "DELETE FROM entries WHERE id = ?1") { stmt in
            sqlite3_bind_int64(stmt, 1, id)
            guard sqlite3_step(stmt) == SQLITE_DONE else { throw StoreError.query(message: lastError) }
        }
    }

    func deleteAll() throws {
        try execute("DELETE FROM entries;")
    }

    func togglePin(id: Int64) throws {
        try statement(sql: "UPDATE entries SET pinned = CASE WHEN pinned = 0 THEN 1 ELSE 0 END WHERE id = ?1") { stmt in
            sqlite3_bind_int64(stmt, 1, id)
            guard sqlite3_step(stmt) == SQLITE_DONE else { throw StoreError.query(message: lastError) }
        }
    }

    private func migrate() throws {
        try execute(
            """
            CREATE TABLE IF NOT EXISTS entries (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                content_type TEXT NOT NULL,
                content     TEXT NOT NULL,
                preview     TEXT NOT NULL,
                hash        TEXT NOT NULL,
                byte_size   INTEGER NOT NULL DEFAULT 0,
                synced      INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT NOT NULL,
                source      TEXT NOT NULL DEFAULT 'local',
                UNIQUE(hash)
            );
            CREATE INDEX IF NOT EXISTS idx_entries_created ON entries(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_entries_hash ON entries(hash);
            """
        )
        if !hasColumn("source") {
            try execute("ALTER TABLE entries ADD COLUMN source TEXT NOT NULL DEFAULT 'local';")
        }
        if !hasColumn("pinned") {
            try execute("ALTER TABLE entries ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0;")
        }
    }

    private func enforceLimit(_ maxEntries: Int) throws {
        try statement(
            sql: """
            DELETE FROM entries WHERE pinned = 0 AND id NOT IN (
                SELECT id FROM entries WHERE pinned = 0 ORDER BY created_at DESC LIMIT ?1
            )
            """
        ) { stmt in
            sqlite3_bind_int64(stmt, 1, Int64(maxEntries))
            guard sqlite3_step(stmt) == SQLITE_DONE else { throw StoreError.query(message: lastError) }
        }
    }

    private func hasColumn(_ column: String) -> Bool {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT \(column) FROM entries LIMIT 0", -1, &stmt, nil) == SQLITE_OK else {
            return false
        }
        sqlite3_finalize(stmt)
        return true
    }

    private func rows(sql: String, bindings: [String]) throws -> [ClipboardEntry] {
        try statement(sql: sql) { stmt in
            for (offset, value) in bindings.enumerated() {
                bind(value, to: stmt, index: Int32(offset + 1))
            }
            var result: [ClipboardEntry] = []
            while true {
                let step = sqlite3_step(stmt)
                if step == SQLITE_ROW {
                    result.append(ClipboardEntry(
                        id: sqlite3_column_int64(stmt, 0),
                        contentType: columnText(stmt, 1),
                        content: columnText(stmt, 2),
                        preview: columnText(stmt, 3),
                        hash: columnText(stmt, 4),
                        byteSize: sqlite3_column_int64(stmt, 5),
                        synced: sqlite3_column_int(stmt, 6) != 0,
                        createdAt: columnText(stmt, 7),
                        source: columnText(stmt, 8),
                        pinned: sqlite3_column_int(stmt, 9) != 0
                    ))
                } else if step == SQLITE_DONE {
                    return result
                } else {
                    throw StoreError.query(message: lastError)
                }
            }
        }
    }

    private func execute(_ sql: String) throws {
        var error: UnsafeMutablePointer<Int8>?
        if sqlite3_exec(db, sql, nil, nil, &error) != SQLITE_OK {
            let message = error.map { String(cString: $0) } ?? lastError
            sqlite3_free(error)
            throw StoreError.query(message: message)
        }
    }

    private func statement<T>(sql: String, run: (OpaquePointer?) throws -> T) throws -> T {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw StoreError.query(message: lastError)
        }
        defer { sqlite3_finalize(stmt) }
        return try run(stmt)
    }

    private var lastError: String {
        if let db, let message = sqlite3_errmsg(db) {
            return String(cString: message)
        }
        return "Unknown SQLite error"
    }
}

enum StoreError: LocalizedError {
    case open(message: String)
    case query(message: String)

    var errorDescription: String? {
        switch self {
        case .open(let message), .query(let message):
            return message
        }
    }
}

private func bind(_ value: String, to stmt: OpaquePointer?, index: Int32) {
    sqlite3_bind_text(stmt, index, value, -1, sqliteTransient)
}

private func columnText(_ stmt: OpaquePointer?, _ index: Int32) -> String {
    guard let cString = sqlite3_column_text(stmt, index) else { return "" }
    return String(cString: cString)
}

enum CapturedClipboard {
    case text(String)
    case url(String)
    case files([String])
    case image(data: Data, width: Int, height: Int, bitsPerPixel: Int)

    var content: RustClipboardContent {
        switch self {
        case .text(let text):
            return .text(text)
        case .url(let url):
            return .url(url)
        case .files(let paths):
            return .files(paths)
        case .image(let data, let width, let height, let bitsPerPixel):
            return .image(RustImageInfo(
                width: width,
                height: height,
                bitsPerPixel: bitsPerPixel,
                dataSize: data.count,
                format: "Png",
                rawData: data.base64EncodedString()
            ))
        }
    }

    var contentType: String {
        content.contentType
    }

    var contentJSON: String {
        content.contentJSON
    }

    var preview: String {
        content.preview()
    }

    var byteSize: Int {
        content.byteSize
    }

    var hash: String {
        content.contentHash
    }

    var debugSummary: String {
        "captured \(content.debugSummary)"
    }
}

final class ClipboardMonitor {
    private let store: ClipboardStore
    private let config: AppConfig
    private var timer: Timer?
    private var lastChangeCount = NSPasteboard.general.changeCount
    private var placeholderRetry: DispatchWorkItem?
    private var placeholderRestoreToken = UUID()
    private let placeholderRestoreDelays: [TimeInterval] = [0.12, 0.35, 0.75, 1.5, 3.0]
    var onChange: (() -> Void)?
    var onCapture: ((CapturedClipboard, Bool) -> Void)?
    var shouldSkipCapture: ((CapturedClipboard) -> Bool)?
    var onExternalPlaceholderInterference: (() -> Void)?

    init(store: ClipboardStore, config: AppConfig) {
        self.store = store
        self.config = config
    }

    func start() {
        timer = Timer.scheduledTimer(withTimeInterval: 0.7, repeats: true) { [weak self] _ in
            self?.poll()
        }
    }

    private func poll() {
        let pasteboard = NSPasteboard.general
        guard pasteboard.changeCount != lastChangeCount else { return }
        lastChangeCount = pasteboard.changeCount

        let rawTypes = pasteboard.types?.map(\.rawValue) ?? []
        oclipLog("clipboard changed count=\(lastChangeCount) types=[\(rawTypes.joined(separator: ", "))]")
        if rawTypes.isEmpty {
            oclipLog("clipboard ignored empty types, possible external placeholder interference")
            onExternalPlaceholderInterference?()
            return
        }
        if rawTypes.contains(selfWriteType.rawValue) {
            oclipLog("clipboard ignored self-write marker")
            return
        }
        if shouldIgnore(types: rawTypes) {
            oclipLog("clipboard ignored concealed/autogenerated/one-time-code types")
            return
        }

        let isTransient = rawTypes.contains { $0.contains("TransientType") }
        let remotePlaceholderPaths = remoteClipboardPlaceholderPaths(from: pasteboard)
        let remotePlaceholderText = remoteClipboardPlaceholderText(from: pasteboard)
        let remotePlaceholderRetryPaths = remotePlaceholderPaths ?? remotePlaceholderText.map { [$0] }
        if let remotePlaceholderRetryPaths {
            oclipLog("clipboard saw remote placeholder transient=\(isTransient) paths=[\(debugFilePaths(remotePlaceholderRetryPaths))]")
        }
        guard let captured = capture(from: pasteboard) else {
            oclipLog("clipboard capture returned nil placeholderRetry=\(remotePlaceholderRetryPaths != nil)")
            if let paths = remotePlaceholderRetryPaths {
                schedulePlaceholderRetry(paths: paths, changeCount: pasteboard.changeCount, isTransient: isTransient)
            }
            return
        }
        oclipLog("clipboard capture ok transient=\(isTransient) restore=\(remotePlaceholderRetryPaths != nil) \(captured.debugSummary)")
        process(
            captured,
            isTransient: isTransient,
            restoreToPasteboard: remotePlaceholderRetryPaths != nil
        )
    }

    private func process(
        _ captured: CapturedClipboard,
        isTransient: Bool,
        restoreToPasteboard: Bool = false
    ) {
        if restoreToPasteboard {
            restoreCapturedContentToPasteboard(captured)
        }

        if shouldSkipCapture?(captured) == true {
            oclipLog("clipboard capture skipped as remote echo \(captured.debugSummary)")
            return
        }
        do {
            try store.insert(captured, maxEntries: config.maxEntries, synced: isTransient)
            oclipLog("clipboard stored local item synced=\(isTransient) \(captured.debugSummary)")
            onCapture?(captured, isTransient)
            onChange?()
        } catch {
            showError("Failed to save clipboard item", message: error.localizedDescription)
        }
    }

    private func restoreCapturedContentToPasteboard(_ captured: CapturedClipboard) {
        let content = captured.content
        do {
            try writeContentToPasteboard(content)
            schedulePlaceholderRestoreGuard(for: content)
            NSLog("o-clip restored remote clipboard placeholder as real clipboard content")
        } catch {
            NSLog("o-clip failed to restore remote clipboard placeholder: \(error.localizedDescription)")
        }
    }

    private func schedulePlaceholderRestoreGuard(for content: RustClipboardContent) {
        guard content.isRestorableAfterExternalPlaceholder else { return }
        placeholderRestoreToken = UUID()
        let token = placeholderRestoreToken
        for (attempt, delay) in placeholderRestoreDelays.enumerated() {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
                guard let self,
                      self.placeholderRestoreToken == token,
                      self.pasteboardWasStolenByRemotePlaceholder() else {
                    return
                }

                do {
                    try writeContentToPasteboard(content)
                    NSLog("o-clip reclaimed clipboard from remote placeholder, attempt \(attempt + 1)")
                } catch {
                    NSLog("o-clip failed to reclaim clipboard from remote placeholder: \(error.localizedDescription)")
                }
            }
        }
    }

    private func pasteboardWasStolenByRemotePlaceholder() -> Bool {
        let pasteboard = NSPasteboard.general
        let rawTypes = pasteboard.types?.map(\.rawValue) ?? []
        if rawTypes.isEmpty { return true }
        if rawTypes.contains(selfWriteType.rawValue) { return false }
        return remoteClipboardPlaceholderPaths(from: pasteboard) != nil
            || remoteClipboardPlaceholderText(from: pasteboard) != nil
    }

    private func shouldIgnore(types: [String]) -> Bool {
        types.contains { type in
            type.contains("ConcealedType") || type.contains("AutoGeneratedType") || type.contains("OneTimeCode")
        }
    }

    private func capture(from pasteboard: NSPasteboard) -> CapturedClipboard? {
        let filePaths = filePaths(from: pasteboard)

        if !filePaths.isEmpty {
            oclipLog("clipboard candidate file paths [\(debugFilePaths(filePaths))]")
            if isRemoteClipboardPlaceholder(paths: filePaths) {
                oclipLog("clipboard file paths are all remote placeholders; trying image payload")
                return captureImage(from: pasteboard) ?? captureImageFromFiles(paths: filePaths)
            }

            let usablePaths = usableClipboardFilePaths(filePaths)
            if usablePaths.isEmpty {
                oclipLog("clipboard file paths unusable after filtering; trying image payload")
                return captureImage(from: pasteboard)
            }
            if usablePaths.count != filePaths.count {
                NSLog("o-clip ignored \(filePaths.count - usablePaths.count) unusable clipboard file path(s)")
            }
            return .files(usablePaths)
        }

        if let image = captureImage(from: pasteboard) {
            return image
        }

        if let placeholderText = remoteClipboardPlaceholderText(from: pasteboard) {
            return captureImageFromFiles(paths: [placeholderText])
        }

        if let url = pasteboard.string(forType: .URL), !url.isEmpty {
            return .url(url)
        }

        if let text = pasteboard.string(forType: .string), !text.isEmpty {
            if let url = URL(string: text), url.scheme != nil, url.host != nil {
                return .url(text)
            }
            return .text(text)
        }

        return nil
    }

    private func filePaths(from pasteboard: NSPasteboard) -> [String] {
        var paths: [String] = []
        if let objects = pasteboard.readObjects(
            forClasses: [NSURL.self],
            options: [.urlReadingFileURLsOnly: true]
        ) as? [NSURL] {
            paths.append(contentsOf: objects.map { $0.path ?? $0.absoluteString ?? "" }.filter { !$0.isEmpty })
        }

        for type in [NSPasteboard.PasteboardType.fileURL, .URL] {
            if let value = pasteboard.string(forType: type),
               let path = filePath(fromPasteboardURLString: value) {
                paths.append(path)
            }
        }

        for item in pasteboard.pasteboardItems ?? [] {
            for type in item.types where type == .fileURL || type == .URL {
                if let value = item.string(forType: type),
                   let path = filePath(fromPasteboardURLString: value) {
                    paths.append(path)
                }
            }
        }

        return Array(Set(paths)).sorted()
    }

    private func filePath(fromPasteboardURLString value: String) -> String? {
        if let url = URL(string: value), url.isFileURL {
            return url.path
        }
        if value.hasPrefix("/") {
            return value
        }
        return nil
    }

    private func captureImage(from pasteboard: NSPasteboard) -> CapturedClipboard? {
        if let png = pasteboard.data(forType: .png),
           let image = capturedImage(fromPNG: png) {
            oclipLog("clipboard captured image from public.png bytes=\(png.count)")
            return image
        }

        if let tiff = pasteboard.data(forType: .tiff),
           let image = NSBitmapImageRep(data: tiff),
           let png = image.representation(using: .png, properties: [:]),
           let pngImage = capturedImage(fromPNG: png) {
            oclipLog("clipboard captured image from public.tiff tiffBytes=\(tiff.count) pngBytes=\(png.count)")
            return pngImage
        }

        return nil
    }

    private func captureImageFromFiles(paths: [String]) -> CapturedClipboard? {
        for path in paths {
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
                  let size = attrs[.size] as? NSNumber,
                  size.int64Value > 0,
                  let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
                continue
            }

            if let pngImage = capturedImage(fromPNG: data) {
                oclipLog("clipboard captured image from file path=\(path) bytes=\(data.count)")
                return pngImage
            }
            if let bitmap = NSBitmapImageRep(data: data),
               let png = bitmap.representation(using: .png, properties: [:]),
               let pngImage = capturedImage(fromPNG: png) {
                oclipLog("clipboard captured image via bitmap path=\(path) fileBytes=\(data.count) pngBytes=\(png.count)")
                return pngImage
            }
        }
        return nil
    }

    private func capturedImage(fromPNG png: Data) -> CapturedClipboard? {
        guard let image = NSBitmapImageRep(data: png) else { return nil }
        let bits = image.bitsPerPixel == 0 ? 32 : image.bitsPerPixel
        return .image(data: png, width: image.pixelsWide, height: image.pixelsHigh, bitsPerPixel: bits)
    }

    private func usableClipboardFilePaths(_ paths: [String]) -> [String] {
        paths.filter { path in
            FileManager.default.fileExists(atPath: path)
                && !isRemoteClipboardPlaceholderPath(path)
        }
    }

    private func remoteClipboardPlaceholderPaths(from pasteboard: NSPasteboard) -> [String]? {
        let paths = filePaths(from: pasteboard)
        return isRemoteClipboardPlaceholder(paths: paths) ? paths : nil
    }

    private func remoteClipboardPlaceholderText(from pasteboard: NSPasteboard) -> String? {
        guard let text = pasteboard.string(forType: .string) else { return nil }
        return normalizedRemoteClipboardPlaceholderText(text)
    }

    private func schedulePlaceholderRetry(paths: [String], changeCount: Int, isTransient: Bool) {
        placeholderRetry?.cancel()

        var attempts = 0
        var workItem: DispatchWorkItem?
        workItem = DispatchWorkItem { [weak self] in
            guard let self,
                  NSPasteboard.general.changeCount == changeCount,
                  workItem?.isCancelled == false else {
                return
            }

            if let captured = self.captureImage(from: .general) ?? self.captureImageFromFiles(paths: paths) {
                NSLog("o-clip captured delayed remote image placeholder")
                self.process(captured, isTransient: isTransient, restoreToPasteboard: true)
                return
            }

            attempts += 1
            if attempts < 12 {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.25, execute: workItem!)
            } else {
                let sizes = paths.map { path -> String in
                    let size = ((try? FileManager.default.attributesOfItem(atPath: path)[.size]) as? NSNumber)?.int64Value ?? -1
                    return "\(URL(fileURLWithPath: path).lastPathComponent):\(size)"
                }.joined(separator: ", ")
                NSLog("o-clip ignored remote placeholder without image data: \(sizes)")
                self.onExternalPlaceholderInterference?()
            }
        }
        placeholderRetry = workItem
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.25, execute: workItem!)
    }

    private func isRemoteClipboardPlaceholder(paths: [String]) -> Bool {
        guard !paths.isEmpty else { return false }
        return paths.allSatisfy(isRemoteClipboardPlaceholderPath)
    }

    private func isRemoteClipboardPlaceholderPath(_ path: String) -> Bool {
        let lowerPath = path.lowercased()
        if lowerPath.contains("com.netease.uuremote.server/clipboard/") {
            return true
        }

        let name = URL(fileURLWithPath: path).lastPathComponent
        return isRemoteClipboardPlaceholderName(name)
    }

    private func normalizedRemoteClipboardPlaceholderText(_ text: String) -> String? {
        let trimmed = text
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        guard !trimmed.isEmpty,
              trimmed.rangeOfCharacter(from: .newlines) == nil else {
            return nil
        }

        if trimmed.lowercased().contains("com.netease.uuremote.server/clipboard/") {
            return trimmed
        }

        let name = trimmed
            .components(separatedBy: CharacterSet(charactersIn: "/\\"))
            .last?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? trimmed
        return isRemoteClipboardPlaceholderName(name) ? trimmed : nil
    }

    private func isRemoteClipboardPlaceholderName(_ name: String) -> Bool {
        let lowerName = name.lowercased()
        if lowerName.hasPrefix(".uuremote_")
            || lowerName.hasPrefix(".1-sunloginclient")
            || lowerName.hasPrefix(".sunloginclient")
            || lowerName.contains("sunloginclient") {
            return true
        }

        return false
    }
}

struct SyncClipboardEntry: Codable {
    var id: Int64
    var contentType: String
    var content: String
    var preview: String
    var hash: String
    var byteSize: Int64
    var synced: Bool
    var createdAt: String
    var clientHash: String

    enum CodingKeys: String, CodingKey {
        case id
        case contentType = "content_type"
        case content
        case preview
        case hash
        case byteSize = "byte_size"
        case synced
        case createdAt = "created_at"
        case clientHash = "client_hash"
    }

    init(content: RustClipboardContent, createdAt: String = ISO8601DateFormatter.oclip.string(from: Date())) {
        self.id = 0
        self.contentType = content.contentType
        self.content = content.contentJSON
        self.preview = content.preview()
        self.hash = content.contentHash
        self.byteSize = Int64(content.byteSize)
        self.synced = false
        self.createdAt = createdAt
        self.clientHash = content.contentHash
    }

    func localEntry(source: String) -> ClipboardEntry {
        let parsed = try? parseClipboardContent(content)
        return ClipboardEntry(
            id: id,
            contentType: contentType,
            content: content,
            preview: preview.isEmpty ? (parsed?.preview() ?? preview) : preview,
            hash: parsed?.contentHash ?? hash,
            byteSize: byteSize,
            synced: true,
            createdAt: createdAt,
            source: source,
            pinned: false
        )
    }

    mutating func replaceContent(_ newContent: RustClipboardContent) {
        contentType = newContent.contentType
        content = newContent.contentJSON
        preview = newContent.preview()
        hash = newContent.contentHash
        byteSize = Int64(newContent.byteSize)
    }
}

private enum SyncClientMessage: Encodable {
    case clipboardEntry(SyncClipboardEntry)
    case syncRequest(limit: Int)
    case auth(password: String)
    case ping

    enum CodingKeys: String, CodingKey {
        case type
        case data
    }

    struct SyncRequestData: Encodable {
        let limit: Int
    }

    struct AuthData: Encodable {
        let password: String
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .clipboardEntry(let entry):
            try container.encode("clipboard_entry", forKey: .type)
            try container.encode(entry, forKey: .data)
        case .syncRequest(let limit):
            try container.encode("sync_request", forKey: .type)
            try container.encode(SyncRequestData(limit: limit), forKey: .data)
        case .auth(let password):
            try container.encode("auth", forKey: .type)
            try container.encode(AuthData(password: password), forKey: .data)
        case .ping:
            try container.encode("ping", forKey: .type)
        }
    }
}

private enum SyncServerMessage: Decodable {
    case clipboardEntry(SyncClipboardEntry)
    case syncResponse(entries: [SyncClipboardEntry], done: Bool)
    case authResult(success: Bool, message: String)
    case error(message: String)
    case pong
    case clearAll

    enum CodingKeys: String, CodingKey {
        case type
        case data
    }

    struct SyncResponseData: Decodable {
        let entries: [SyncClipboardEntry]
        let done: Bool?
    }

    struct AuthResultData: Decodable {
        let success: Bool
        let message: String
    }

    struct ErrorData: Decodable {
        let message: String
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(String.self, forKey: .type)
        switch type {
        case "clipboard_entry":
            self = .clipboardEntry(try container.decode(SyncClipboardEntry.self, forKey: .data))
        case "sync_response":
            let data = try container.decode(SyncResponseData.self, forKey: .data)
            self = .syncResponse(entries: data.entries, done: data.done ?? false)
        case "auth_result":
            let data = try container.decode(AuthResultData.self, forKey: .data)
            self = .authResult(success: data.success, message: data.message)
        case "error":
            let data = try container.decode(ErrorData.self, forKey: .data)
            self = .error(message: data.message)
        case "pong":
            self = .pong
        case "clear_all":
            self = .clearAll
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .type,
                in: container,
                debugDescription: "Unknown sync message type: \(type)"
            )
        }
    }
}

extension SyncClipboardEntry {
    var debugSummary: String {
        if let parsed = try? parseClipboardContent(content) {
            return "entry id=\(id) sourceHash=\(shortHash(hash)) clientHash=\(shortHash(clientHash)) synced=\(synced) created=\(createdAt) \(parsed.debugSummary)"
        }
        return "entry id=\(id) type=\(contentType) bytes=\(byteSize) sourceHash=\(shortHash(hash)) clientHash=\(shortHash(clientHash)) synced=\(synced) created=\(createdAt) contentDecode=failed"
    }
}

private extension SyncClientMessage {
    var debugSummary: String {
        switch self {
        case .clipboardEntry(let entry):
            return "clipboard_entry \(entry.debugSummary)"
        case .syncRequest(let limit):
            return "sync_request limit=\(limit)"
        case .auth:
            return "auth password=present"
        case .ping:
            return "ping"
        }
    }
}

private extension SyncServerMessage {
    var debugSummary: String {
        switch self {
        case .clipboardEntry(let entry):
            return "clipboard_entry \(entry.debugSummary)"
        case .syncResponse(let entries, let done):
            let sample = entries.prefix(3).map(\.debugSummary).joined(separator: " | ")
            return "sync_response count=\(entries.count) done=\(done) sample=[\(sample)]"
        case .authResult(let success, let message):
            return "auth_result success=\(success) message=\(message)"
        case .error(let message):
            return "error message=\(message)"
        case .pong:
            return "pong"
        case .clearAll:
            return "clear_all"
        }
    }
}

private struct UploadResponse: Decodable {
    let files: [FileRef]
}

final class SyncCoordinator: NSObject, URLSessionDelegate {
    private let config: AppConfig
    private let store: ClipboardStore
    private let queue = DispatchQueue(label: "com.boninall.oclip.sync")
    private lazy var session: URLSession = {
        let configuration = URLSessionConfiguration.default
        configuration.timeoutIntervalForRequest = 30
        return URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    }()
    private var wsTask: URLSessionWebSocketTask?
    private var stopped = false
    private var connectionGeneration: UInt64 = 0
    private var reconnectGeneration: UInt64 = 0
    private var reconnectScheduled = false
    private var reconnectDelay: TimeInterval = 1
    private let recentRemoteHashLock = NSLock()
    private let remoteEchoTTL: TimeInterval = 10
    private let remoteAutoCopyTTL: TimeInterval = 5
    private let remoteRestoreTTL: TimeInterval = 60
    private var recentRemoteHashes: [String: Date] = [:]
    private var remoteAutoCopyInFlight: Set<String> = []
    private var recentRemoteAutoCopyKeys: [String: Date] = [:]
    private var lastAutoCopiedRemoteContent: RustClipboardContent?
    private var lastAutoCopiedRemoteAt: Date?
    private var remotePasteboardGuardToken = UUID()
    private let remotePasteboardGuardDelays: [TimeInterval] = [0.12, 0.35, 0.75, 1.5, 3.0]
    var onChange: (() -> Void)?

    init(config: AppConfig, store: ClipboardStore) {
        self.config = config
        self.store = store
        super.init()
        try? FileManager.default.createDirectory(
            at: config.resolvedDownloadDirectory,
            withIntermediateDirectories: true
        )
        oclipLog("sync init serverURL=\(config.serverURL) autoConnect=\(config.autoConnect) maxSync=\(config.maxSyncSize) maxFile=\(config.maxFileSyncSize) inlineImage=\(config.imageInlineThreshold) downloadDir=\(config.resolvedDownloadDirectory.path)")
    }

    func start() {
        guard config.autoConnect, !config.serverURL.isEmpty else {
            oclipLog("sync start skipped autoConnect=\(config.autoConnect) serverURLSet=\(!config.serverURL.isEmpty)")
            return
        }
        oclipLog("sync start requested")
        stopped = false
        queue.async { [weak self] in
            self?.connect()
        }
    }

    func stop() {
        oclipLog("sync stop requested")
        stopped = true
        connectionGeneration += 1
        reconnectGeneration += 1
        wsTask?.cancel(with: .goingAway, reason: nil)
        wsTask = nil
    }

    var canReconnect: Bool {
        !config.serverURL.isEmpty
    }

    func reconnect() {
        guard canReconnect else {
            oclipLog("sync reconnect skipped because serverURL is empty")
            return
        }
        oclipLog("sync reconnect requested")
        stopped = false
        queue.async { [weak self] in
            self?.connect()
        }
    }

    func handleLocalCapture(_ captured: CapturedClipboard, noCloud: Bool) {
        let content = captured.content
        oclipLog("local capture received noCloud=\(noCloud) autoConnect=\(config.autoConnect) serverURLSet=\(!config.serverURL.isEmpty) \(content.debugSummary)")
        guard !noCloud else {
            oclipLog("local sync skipped because clipboard item is transient/no-cloud")
            return
        }
        guard config.autoConnect else {
            oclipLog("local sync skipped because autoConnect=false")
            return
        }
        guard !config.serverURL.isEmpty else {
            oclipLog("local sync skipped because serverURL is empty")
            return
        }
        let entry = SyncClipboardEntry(content: content)

        queue.async { [weak self] in
            guard let self else { return }
            switch content {
            case .files(let paths):
                oclipLog("local file sync uploading paths=[\(debugFilePaths(paths))]")
                self.uploadFiles(paths: paths) { refs in
                    guard let refs, !refs.isEmpty else {
                        oclipLog("local file sync upload returned no refs")
                        return
                    }
                    var syncedEntry = entry
                    syncedEntry.replaceContent(.syncedFiles(refs))
                    oclipLog("local file sync sending refs=[\(debugFileRefs(refs))]")
                    self.send(.clipboardEntry(syncedEntry))
                }
            case .image(let image):
                guard image.rawData != nil else {
                    oclipLog("local image sync skipped because rawData=nil \(image.debugSummary)")
                    return
                }
                if image.dataSize <= self.config.imageInlineThreshold,
                   entry.byteSize <= self.config.maxSyncSize {
                    oclipLog("local image sync sending inline \(image.debugSummary) threshold=\(self.config.imageInlineThreshold)")
                    self.send(.clipboardEntry(entry))
                } else {
                    oclipLog("local image sync uploading before send \(image.debugSummary) inlineThreshold=\(self.config.imageInlineThreshold) maxFile=\(self.config.maxFileSyncSize)")
                    self.uploadImage(image) { imageRef in
                        guard let imageRef else {
                            oclipLog("local image sync upload returned no image ref")
                            return
                        }
                        var syncedEntry = entry
                        syncedEntry.replaceContent(.syncedImage(imageRef))
                        oclipLog("local image sync sending image ref \(imageRef.debugSummary)")
                        self.send(.clipboardEntry(syncedEntry))
                    }
                }
            case .text, .url:
                if entry.byteSize <= self.config.maxSyncSize {
                    oclipLog("local text/url sync sending \(entry.debugSummary)")
                    self.send(.clipboardEntry(entry))
                } else {
                    oclipLog("local text/url sync skipped size=\(entry.byteSize) max=\(self.config.maxSyncSize)")
                }
            case .syncedFiles, .syncedImage:
                oclipLog("local sync skipped already-synced content \(content.debugSummary)")
                break
            }
        }
    }

    func shouldSkipLocalCapture(_ captured: CapturedClipboard) -> Bool {
        consumeRemoteEcho(hash: captured.hash)
    }

    func copyRemoteContentIfNeeded(_ entry: ClipboardEntry) -> Bool {
        guard let content = try? parseClipboardContent(entry.content) else { return false }
        switch content {
        case .syncedFiles, .syncedImage:
            oclipLog("manual remote copy requires sync entryId=\(entry.id) \(content.debugSummary)")
            autoCopy(content)
            return true
        case .text, .url, .files, .image:
            oclipLog("manual remote copy can use direct pasteboard entryId=\(entry.id) \(content.debugSummary)")
            return false
        }
    }

    func restoreAfterExternalPlaceholder() {
        guard let content = recentAutoCopiedRemoteContentForRestore() else {
            NSLog("o-clip saw external placeholder but has no recent remote content to restore")
            return
        }

        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.rememberRemoteEcho(content)
            do {
                try writeContentToPasteboard(content)
                self.recordAutoCopiedRemote(content)
                NSLog("o-clip restored remote \(content.contentType) after external placeholder")
                oclipLog("remote placeholder restore wrote pasteboard \(content.debugSummary)")
            } catch {
                NSLog("o-clip failed to restore remote content after placeholder: \(error.localizedDescription)")
            }
        }
    }

    private func connect() {
        guard !stopped, let url = URL(string: config.serverURL) else {
            oclipLog("sync connect skipped stopped=\(stopped) serverURL=\(config.serverURL)")
            return
        }
        connectionGeneration += 1
        reconnectGeneration += 1
        let generation = connectionGeneration
        reconnectScheduled = false
        wsTask?.cancel(with: .goingAway, reason: nil)
        let task = session.webSocketTask(with: url)
        task.maximumMessageSize = max(config.maxSyncSize * 2, 16 * 1024 * 1024)
        wsTask = task
        task.resume()
        reconnectDelay = 1
        oclipLog("sync connecting generation=\(generation) url=\(url.absoluteString) maxMessage=\(task.maximumMessageSize)")

        if let password = config.password, !password.isEmpty {
            oclipLog("sync sending auth generation=\(generation)")
            send(.auth(password: password), generation: generation)
        } else {
            oclipLog("sync requesting initial history generation=\(generation)")
            send(.syncRequest(limit: 50), generation: generation)
        }
        receiveNext(generation: generation)
        schedulePing(generation: generation)
    }

    private func receiveNext(generation: UInt64) {
        wsTask?.receive { [weak self] result in
            guard let self else { return }
            self.queue.async {
                guard !self.stopped,
                      self.connectionGeneration == generation else {
                    return
                }
                switch result {
                case .success(let message):
                    switch message {
                    case .string(let text):
                        oclipLog("sync received ws string generation=\(generation) bytes=\(text.utf8.count)")
                        self.handleServerText(text, generation: generation)
                    case .data:
                        oclipLog("sync received unsupported ws data generation=\(generation)")
                        break
                    @unknown default:
                        oclipLog("sync received unknown ws message generation=\(generation)")
                        break
                    }
                    if !self.stopped, self.connectionGeneration == generation {
                        self.receiveNext(generation: generation)
                    }
                case .failure(let error):
                    NSLog("o-clip sync receive failed: \(error.localizedDescription)")
                    self.scheduleReconnect(generation: generation)
                }
            }
        }
    }

    private func handleServerText(_ text: String, generation: UInt64) {
        guard let data = text.data(using: .utf8),
              let message = try? jsonDecoder.decode(SyncServerMessage.self, from: data) else {
            oclipLog("sync failed to decode server message generation=\(generation) bytes=\(text.utf8.count)")
            return
        }
        oclipLog("sync decoded server message generation=\(generation) \(message.debugSummary)")

        switch message {
        case .clipboardEntry(let entry):
            handleRemoteEntry(entry, shouldAutoCopy: true)
        case .syncResponse(let entries, _):
            for entry in entries {
                handleRemoteEntry(entry, shouldAutoCopy: false)
            }
        case .authResult(let success, let message):
            if success {
                oclipLog("sync auth success, requesting history generation=\(generation)")
                send(.syncRequest(limit: 50), generation: generation)
            } else {
                NSLog("o-clip sync auth failed: \(message)")
                scheduleReconnect(generation: generation)
            }
        case .error(let message):
            NSLog("o-clip sync server error: \(message)")
        case .pong:
            break
        case .clearAll:
            do {
                try store.deleteAll()
                DispatchQueue.main.async { [weak self] in self?.onChange?() }
            } catch {
                NSLog("o-clip failed to clear local store: \(error.localizedDescription)")
            }
        }
    }

    private func handleRemoteEntry(_ syncEntry: SyncClipboardEntry, shouldAutoCopy: Bool) {
        let entry = syncEntry.localEntry(source: "remote")
        do {
            let alreadyExists = try store.hasHash(entry.hash)
                || (!syncEntry.clientHash.isEmpty && (try store.hasHash(syncEntry.clientHash)))
            let content = try? parseClipboardContent(entry.content)
            oclipLog("remote entry received shouldAutoCopy=\(shouldAutoCopy) alreadyExists=\(alreadyExists) localHash=\(shortHash(entry.hash)) \(syncEntry.debugSummary)")
            if let content, shouldDropRemoteContent(content) {
                NSLog("o-clip ignored remote placeholder file entry")
                return
            }
            if !alreadyExists {
                try store.insert(entry, maxEntries: config.maxEntries)
                oclipLog("remote entry stored \(syncEntry.debugSummary)")
                DispatchQueue.main.async { [weak self] in self?.onChange?() }
            } else {
                oclipLog("remote entry not stored because duplicate hash/clientHash")
            }
            if shouldAutoCopy, let content {
                guard let autoCopyKey = beginRemoteAutoCopy(content) else {
                    NSLog("o-clip skipped duplicate remote auto-copy for \(content.contentType)")
                    return
                }
                oclipLog("remote auto-copy starting key=\(autoCopyKey) \(content.debugSummary)")
                rememberRemoteEcho(content)
                autoCopy(content, autoCopyKey: autoCopyKey)
            } else if shouldAutoCopy {
                oclipLog("remote auto-copy skipped because content decode failed")
            } else {
                oclipLog("remote auto-copy skipped for sync response/history")
            }
        } catch {
            NSLog("o-clip failed to store remote entry: \(error.localizedDescription)")
        }
    }

    private func autoCopy(_ content: RustClipboardContent, autoCopyKey: String? = nil) {
        switch content {
        case .syncedFiles(let refs):
            oclipLog("auto-copy synced files requested refs=[\(debugFileRefs(refs))]")
            guard !isRemotePlaceholderFileRefs(refs) else {
                NSLog("o-clip skipped remote placeholder file auto-copy")
                if let autoCopyKey { finishRemoteAutoCopy(autoCopyKey) }
                return
            }
            downloadFiles(refs: refs) { paths in
                guard let paths, !paths.isEmpty else {
                    NSLog("o-clip failed to download synced files for auto-copy")
                    if let autoCopyKey { self.finishRemoteAutoCopy(autoCopyKey) }
                    return
                }
                let downloadedContent = RustClipboardContent.files(paths)
                self.rememberRemoteEcho(downloadedContent)
                oclipLog("auto-copy synced files downloaded paths=[\(debugFilePaths(paths))]")
                DispatchQueue.main.async {
                    defer {
                        if let autoCopyKey { self.finishRemoteAutoCopy(autoCopyKey) }
                    }
                    do {
                        try writeContentToPasteboard(downloadedContent)
                        self.recordAutoCopiedRemote(downloadedContent)
                        oclipLog("auto-copy synced files wrote pasteboard \(downloadedContent.debugSummary)")
                    } catch {
                        NSLog("o-clip failed to copy downloaded files: \(error.localizedDescription)")
                    }
                }
            }
        case .syncedImage(let imageRef):
            oclipLog("auto-copy synced image requested \(imageRef.debugSummary)")
            downloadImage(imageRef: imageRef) { image in
                guard let image else {
                    NSLog("o-clip failed to download synced image for auto-copy")
                    if let autoCopyKey { self.finishRemoteAutoCopy(autoCopyKey) }
                    return
                }
                let downloadedContent = RustClipboardContent.image(image)
                self.rememberRemoteEcho(downloadedContent)
                oclipLog("auto-copy synced image downloaded \(image.debugSummary)")
                DispatchQueue.main.async {
                    defer {
                        if let autoCopyKey { self.finishRemoteAutoCopy(autoCopyKey) }
                    }
                    do {
                        try writeContentToPasteboard(downloadedContent)
                        self.recordAutoCopiedRemote(downloadedContent)
                        oclipLog("auto-copy synced image wrote pasteboard \(downloadedContent.debugSummary)")
                    } catch {
                        NSLog("o-clip failed to copy downloaded image: \(error.localizedDescription)")
                    }
                }
            }
        case .text, .url, .files, .image:
            oclipLog("auto-copy direct content requested \(content.debugSummary)")
            rememberRemoteEcho(content)
            DispatchQueue.main.async {
                defer {
                    if let autoCopyKey { self.finishRemoteAutoCopy(autoCopyKey) }
                }
                do {
                    try writeContentToPasteboard(content)
                    self.recordAutoCopiedRemote(content)
                    oclipLog("auto-copy direct content wrote pasteboard \(content.debugSummary)")
                } catch {
                    NSLog("o-clip failed to copy remote content: \(error.localizedDescription)")
                }
            }
        }
    }

    private func beginRemoteAutoCopy(_ content: RustClipboardContent) -> String? {
        let key = remoteAutoCopyKey(for: content)
        let now = Date()
        recentRemoteHashLock.lock()
        pruneRemoteAutoCopyKeys(now: now)
        defer { recentRemoteHashLock.unlock() }

        if remoteAutoCopyInFlight.contains(key) || recentRemoteAutoCopyKeys[key] != nil {
            oclipLog("remote auto-copy dedupe hit key=\(key)")
            return nil
        }

        remoteAutoCopyInFlight.insert(key)
        oclipLog("remote auto-copy registered key=\(key)")
        return key
    }

    private func finishRemoteAutoCopy(_ key: String) {
        recentRemoteHashLock.lock()
        remoteAutoCopyInFlight.remove(key)
        recentRemoteAutoCopyKeys[key] = Date()
        recentRemoteHashLock.unlock()
        oclipLog("remote auto-copy finished key=\(key)")
    }

    private func remoteAutoCopyKey(for content: RustClipboardContent) -> String {
        switch content {
        case .syncedFiles(let refs):
            let ids = refs.map(\.fileId).sorted().joined(separator: "\u{0}")
            return "syncedFiles:\(ids)"
        case .syncedImage(let image):
            return "syncedImage:\(image.imageId)"
        default:
            return "\(content.contentType):\(content.contentHash)"
        }
    }

    private func recordAutoCopiedRemote(_ content: RustClipboardContent, scheduleGuard: Bool = true) {
        guard content.isRestorableAfterExternalPlaceholder else { return }
        recentRemoteHashLock.lock()
        lastAutoCopiedRemoteContent = content
        lastAutoCopiedRemoteAt = Date()
        recentRemoteHashLock.unlock()

        if scheduleGuard {
            DispatchQueue.main.async { [weak self] in
                self?.scheduleRemotePasteboardGuard(for: content)
            }
        }
    }

    private func scheduleRemotePasteboardGuard(for content: RustClipboardContent) {
        guard content.isRestorableAfterExternalPlaceholder else { return }
        remotePasteboardGuardToken = UUID()
        let token = remotePasteboardGuardToken
        for (attempt, delay) in remotePasteboardGuardDelays.enumerated() {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
                guard let self,
                      self.remotePasteboardGuardToken == token,
                      self.pasteboardWasStolenByRemotePlaceholder() else {
                    return
                }

                    self.rememberRemoteEcho(content)
                    do {
                        try writeContentToPasteboard(content)
                        self.recordAutoCopiedRemote(content, scheduleGuard: false)
                        NSLog("o-clip reclaimed remote \(content.contentType) clipboard from placeholder, attempt \(attempt + 1)")
                        oclipLog("remote pasteboard guard rewrote content attempt=\(attempt + 1) \(content.debugSummary)")
                    } catch {
                    NSLog("o-clip failed to reclaim remote clipboard from placeholder: \(error.localizedDescription)")
                }
            }
        }
    }

    private func pasteboardWasStolenByRemotePlaceholder() -> Bool {
        let pasteboard = NSPasteboard.general
        let rawTypes = pasteboard.types?.map(\.rawValue) ?? []
        if rawTypes.isEmpty { return true }
        if rawTypes.contains(selfWriteType.rawValue) { return false }
        return remoteClipboardPlaceholderPaths(from: pasteboard) != nil
            || remoteClipboardPlaceholderText(from: pasteboard) != nil
    }

    private func remoteClipboardPlaceholderPaths(from pasteboard: NSPasteboard) -> [String]? {
        let paths = filePaths(from: pasteboard)
        return isRemoteClipboardPlaceholder(paths: paths) ? paths : nil
    }

    private func remoteClipboardPlaceholderText(from pasteboard: NSPasteboard) -> String? {
        guard let text = pasteboard.string(forType: .string) else { return nil }
        return normalizedRemoteClipboardPlaceholderText(text)
    }

    private func filePaths(from pasteboard: NSPasteboard) -> [String] {
        var paths: [String] = []
        if let objects = pasteboard.readObjects(
            forClasses: [NSURL.self],
            options: [.urlReadingFileURLsOnly: true]
        ) as? [NSURL] {
            paths.append(contentsOf: objects.map { $0.path ?? $0.absoluteString ?? "" }.filter { !$0.isEmpty })
        }

        for type in [NSPasteboard.PasteboardType.fileURL, .URL] {
            if let value = pasteboard.string(forType: type),
               let path = filePath(fromPasteboardURLString: value) {
                paths.append(path)
            }
        }

        for item in pasteboard.pasteboardItems ?? [] {
            for type in item.types where type == .fileURL || type == .URL {
                if let value = item.string(forType: type),
                   let path = filePath(fromPasteboardURLString: value) {
                    paths.append(path)
                }
            }
        }

        return Array(Set(paths)).sorted()
    }

    private func filePath(fromPasteboardURLString value: String) -> String? {
        if let url = URL(string: value), url.isFileURL {
            return url.path
        }
        if value.hasPrefix("/") {
            return value
        }
        return nil
    }

    private func isRemoteClipboardPlaceholder(paths: [String]) -> Bool {
        guard !paths.isEmpty else { return false }
        return paths.allSatisfy(isRemoteClipboardPlaceholderPath)
    }

    private func isRemoteClipboardPlaceholderPath(_ path: String) -> Bool {
        let lowerPath = path.lowercased()
        if lowerPath.contains("com.netease.uuremote.server/clipboard/") {
            return true
        }

        let name = URL(fileURLWithPath: path).lastPathComponent
        return isRemoteClipboardPlaceholderName(name)
    }

    private func normalizedRemoteClipboardPlaceholderText(_ text: String) -> String? {
        let trimmed = text
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        guard !trimmed.isEmpty,
              trimmed.rangeOfCharacter(from: .newlines) == nil else {
            return nil
        }

        if trimmed.lowercased().contains("com.netease.uuremote.server/clipboard/") {
            return trimmed
        }

        let name = trimmed
            .components(separatedBy: CharacterSet(charactersIn: "/\\"))
            .last?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? trimmed
        return isRemoteClipboardPlaceholderName(name) ? trimmed : nil
    }

    private func isRemoteClipboardPlaceholderName(_ name: String) -> Bool {
        let lowerName = name.lowercased()
        if lowerName.hasPrefix(".uuremote_")
            || lowerName.hasPrefix(".1-sunloginclient")
            || lowerName.hasPrefix(".sunloginclient")
            || lowerName.contains("sunloginclient") {
            return true
        }

        return false
    }

    private func shouldDropRemoteContent(_ content: RustClipboardContent) -> Bool {
        switch content {
        case .syncedFiles(let refs):
            return isRemotePlaceholderFileRefs(refs)
        case .text, .url, .files, .image, .syncedImage:
            return false
        }
    }

    private func isRemotePlaceholderFileRefs(_ refs: [FileRef]) -> Bool {
        guard !refs.isEmpty else { return false }
        return refs.allSatisfy { ref in
            ref.size == 0 && isRemoteClipboardPlaceholderName(ref.filename)
        }
    }

    private func recentAutoCopiedRemoteContentForRestore() -> RustClipboardContent? {
        recentRemoteHashLock.lock()
        defer { recentRemoteHashLock.unlock() }
        guard let content = lastAutoCopiedRemoteContent,
              let at = lastAutoCopiedRemoteAt,
              Date().timeIntervalSince(at) < remoteRestoreTTL else {
            return nil
        }
        return content
    }

    private func rememberRemoteEcho(_ content: RustClipboardContent) {
        rememberRemoteEcho(hash: content.contentHash)
    }

    private func rememberRemoteEcho(hash: String) {
        guard !hash.isEmpty else { return }
        recentRemoteHashLock.lock()
        pruneRemoteEchoHashes(now: Date())
        recentRemoteHashes[hash] = Date()
        recentRemoteHashLock.unlock()
    }

    private func consumeRemoteEcho(hash: String) -> Bool {
        guard !hash.isEmpty else { return false }
        let now = Date()
        recentRemoteHashLock.lock()
        pruneRemoteEchoHashes(now: now)
        let matched = recentRemoteHashes.removeValue(forKey: hash) != nil
        recentRemoteHashLock.unlock()
        if matched {
            NSLog("o-clip skipped local echo for remote content: \(hash.prefix(16))")
        }
        return matched
    }

    private func pruneRemoteEchoHashes(now: Date) {
        recentRemoteHashes = recentRemoteHashes.filter { now.timeIntervalSince($0.value) < remoteEchoTTL }
    }

    private func pruneRemoteAutoCopyKeys(now: Date) {
        recentRemoteAutoCopyKeys = recentRemoteAutoCopyKeys.filter {
            now.timeIntervalSince($0.value) < remoteAutoCopyTTL
        }
    }

    private func send(_ message: SyncClientMessage, generation: UInt64? = nil) {
        queue.async { [weak self] in
            self?.sendOnQueue(message, generation: generation)
        }
    }

    private func sendOnQueue(_ message: SyncClientMessage, generation: UInt64? = nil) {
        let sendGeneration = generation ?? connectionGeneration
        guard !stopped,
              connectionGeneration == sendGeneration,
              let wsTask else {
            oclipLog("sync send skipped generation=\(sendGeneration) current=\(connectionGeneration) stopped=\(stopped) hasTask=\(wsTask != nil) message=\(message.debugSummary)")
            return
        }
        guard let data = try? jsonEncoder.encode(message),
              let text = String(data: data, encoding: .utf8) else {
            oclipLog("sync send encode failed message=\(message.debugSummary)")
            return
        }
        oclipLog("sync sending generation=\(sendGeneration) bytes=\(text.utf8.count) \(message.debugSummary)")
        wsTask.send(.string(text)) { [weak self] error in
            if let error {
                NSLog("o-clip sync send failed: \(error.localizedDescription)")
                self?.scheduleReconnect(generation: sendGeneration)
            } else {
                oclipLog("sync send ok generation=\(sendGeneration) \(message.debugSummary)")
            }
        }
    }

    private func schedulePing(generation: UInt64) {
        queue.asyncAfter(deadline: .now() + 30) { [weak self] in
            guard let self,
                  !self.stopped,
                  self.connectionGeneration == generation else {
                return
            }
            self.send(.ping, generation: generation)
            self.schedulePing(generation: generation)
        }
    }

    private func scheduleReconnect(generation: UInt64? = nil) {
        queue.async { [weak self] in
            guard let self, !self.stopped, !self.reconnectScheduled else { return }
            if let generation, self.connectionGeneration != generation {
                oclipLog("sync reconnect skipped stale generation requested=\(generation) current=\(self.connectionGeneration)")
                return
            }
            self.reconnectScheduled = true
            self.connectionGeneration += 1
            self.wsTask?.cancel(with: .goingAway, reason: nil)
            self.wsTask = nil
            self.reconnectGeneration += 1
            let reconnectGeneration = self.reconnectGeneration
            let delay = self.reconnectDelay
            self.reconnectDelay = min(self.reconnectDelay * 2, 30)
            oclipLog("sync reconnect scheduled delay=\(delay) generation=\(reconnectGeneration)")
            self.queue.asyncAfter(deadline: .now() + delay) { [weak self] in
                guard let self,
                      !self.stopped,
                      self.reconnectGeneration == reconnectGeneration else {
                    oclipLog("sync reconnect canceled generation=\(reconnectGeneration)")
                    return
                }
                self.connect()
            }
        }
    }

    private func uploadFiles(paths: [String], completion: @escaping ([FileRef]?) -> Void) {
        oclipLog("upload files requested paths=[\(debugFilePaths(paths))]")
        let filteredPaths = paths.filter { !isRemoteClipboardPlaceholderPath($0) }
        if filteredPaths.count != paths.count {
            NSLog("o-clip skipped \(paths.count - filteredPaths.count) remote placeholder file upload(s)")
        }

        let parts = filteredPaths.compactMap { path -> MultipartPart? in
            let url = URL(fileURLWithPath: path)
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
                  let size = attrs[.size] as? NSNumber,
                  size.int64Value <= Int64(config.maxFileSyncSize),
                  let data = try? Data(contentsOf: url) else {
                oclipLog("upload files skipped path=\(path) maxFile=\(config.maxFileSyncSize)")
                return nil
            }
            oclipLog("upload files prepared part filename=\(url.lastPathComponent) size=\(data.count) mime=\(mimeType(for: url))")
            return MultipartPart(
                fieldName: "file",
                filename: url.lastPathComponent.isEmpty ? "unnamed" : url.lastPathComponent,
                mimeType: mimeType(for: url),
                data: data
            )
        }
        guard !parts.isEmpty else {
            oclipLog("upload files aborted because no multipart parts")
            completion(nil)
            return
        }
        oclipLog("upload files starting partCount=\(parts.count)")
        upload(parts: parts) { response in
            if let response {
                oclipLog("upload files response refs=[\(debugFileRefs(response.files))]")
            } else {
                oclipLog("upload files response nil")
            }
            completion(response?.files)
        }
    }

    private func uploadImage(_ image: RustImageInfo, completion: @escaping (ImageRef?) -> Void) {
        guard let raw = image.rawData,
              let data = Data(base64Encoded: raw),
              data.count <= config.maxFileSyncSize else {
            oclipLog("upload image skipped rawPresent=\(image.rawData != nil) size=\(image.dataSize) maxFile=\(config.maxFileSyncSize)")
            completion(nil)
            return
        }
        oclipLog("upload image starting \(image.debugSummary) uploadBytes=\(data.count)")
        let isPng = image.format == "Png"
        let part = MultipartPart(
            fieldName: "file",
            filename: isPng ? "image.png" : "image.bmp",
            mimeType: isPng ? "image/png" : "image/bmp",
            data: data
        )
        upload(parts: [part]) { response in
            guard let fileRef = response?.files.first else {
                oclipLog("upload image response missing file ref")
                completion(nil)
                return
            }
            oclipLog("upload image response ref=\(fileRef.debugSummary)")
            completion(ImageRef(
                imageId: fileRef.fileId,
                width: image.width,
                height: image.height,
                bitsPerPixel: image.bitsPerPixel,
                format: image.format,
                size: fileRef.size
            ))
        }
    }

    private struct MultipartPart {
        let fieldName: String
        let filename: String
        let mimeType: String
        let data: Data
    }

    private func upload(parts: [MultipartPart], completion: @escaping (UploadResponse?) -> Void) {
        guard let url = httpBaseURL()?.appendingPathComponent("files").appendingPathComponent("upload") else {
            oclipLog("upload failed: invalid HTTP base URL serverURL=\(config.serverURL)")
            completion(nil)
            return
        }
        let boundary = "----oclip-\(UUID().uuidString)"
        var request = authorizedRequest(url: url, method: "POST")
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")

        var body = Data()
        for part in parts {
            body.appendString("--\(boundary)\r\n")
            body.appendString("Content-Disposition: form-data; name=\"\(part.fieldName)\"; filename=\"\(part.filename.replacingOccurrences(of: "\"", with: "'"))\"\r\n")
            body.appendString("Content-Type: \(part.mimeType)\r\n\r\n")
            body.append(part.data)
            body.appendString("\r\n")
        }
        body.appendString("--\(boundary)--\r\n")
        oclipLog("upload HTTP request url=\(url.absoluteString) parts=\(parts.count) bodyBytes=\(body.count)")

        session.uploadTask(with: request, from: body) { data, response, error in
            if let error {
                NSLog("o-clip upload failed: \(error.localizedDescription)")
                completion(nil)
                return
            }
            guard self.isSuccess(response),
                  let data,
                  let decoded = try? jsonDecoder.decode(UploadResponse.self, from: data) else {
                if let http = response as? HTTPURLResponse {
                    NSLog("o-clip upload failed with status: \(http.statusCode)")
                } else {
                    NSLog("o-clip upload failed: invalid response")
                }
                completion(nil)
                return
            }
            if let http = response as? HTTPURLResponse {
                oclipLog("upload HTTP ok status=\(http.statusCode) responseBytes=\(data.count) refs=[\(debugFileRefs(decoded.files))]")
            }
            completion(decoded)
        }.resume()
    }

    private func downloadFiles(refs: [FileRef], completion: @escaping ([String]?) -> Void) {
        guard let baseURL = httpBaseURL() else {
            NSLog("o-clip file download failed: invalid server URL")
            completion(nil)
            return
        }
        guard !refs.isEmpty else {
            completion(nil)
            return
        }
        oclipLog("download files requested refs=[\(debugFileRefs(refs))] baseURL=\(baseURL.absoluteString)")

        let group = DispatchGroup()
        let lock = NSLock()
        var paths: [String] = []

        for ref in refs {
            group.enter()
            let url = baseURL.appendingPathComponent("files").appendingPathComponent(ref.fileId)
            oclipLog("download file starting url=\(url.absoluteString) ref=\(ref.debugSummary)")
            session.dataTask(with: authorizedRequest(url: url, method: "GET")) { data, response, error in
                defer { group.leave() }
                if let error {
                    NSLog("o-clip file download failed: \(error.localizedDescription)")
                    return
                }
                guard self.isSuccess(response), let data else {
                    if let http = response as? HTTPURLResponse {
                        NSLog("o-clip file download failed with status \(http.statusCode) for \(ref.filename) (\(ref.fileId))")
                    } else {
                        NSLog("o-clip file download failed: invalid response for \(ref.filename) (\(ref.fileId))")
                    }
                    return
                }
                if let http = response as? HTTPURLResponse {
                    oclipLog("download file HTTP ok status=\(http.statusCode) bytes=\(data.count) ref=\(ref.debugSummary)")
                }
                let localURL = self.uniqueDownloadURL(filename: ref.filename)
                do {
                    try data.write(to: localURL)
                    lock.lock()
                    paths.append(localURL.path)
                    lock.unlock()
                    oclipLog("download file wrote path=\(localURL.path) bytes=\(data.count)")
                } catch {
                    NSLog("o-clip failed to write downloaded file: \(error.localizedDescription)")
                }
            }.resume()
        }

        group.notify(queue: queue) {
            oclipLog("download files finished count=\(paths.count) paths=[\(debugFilePaths(paths))]")
            completion(paths.isEmpty ? nil : paths)
        }
    }

    private func downloadImage(imageRef: ImageRef, completion: @escaping (RustImageInfo?) -> Void) {
        guard let baseURL = httpBaseURL() else {
            oclipLog("image download failed: invalid server URL")
            completion(nil)
            return
        }
        let url = baseURL.appendingPathComponent("files").appendingPathComponent(imageRef.imageId)
        oclipLog("image download starting url=\(url.absoluteString) ref=\(imageRef.debugSummary)")
        session.dataTask(with: authorizedRequest(url: url, method: "GET")) { data, response, error in
            if let error {
                NSLog("o-clip image download failed: \(error.localizedDescription)")
                completion(nil)
                return
            }
            guard self.isSuccess(response), let data else {
                if let http = response as? HTTPURLResponse {
                    NSLog("o-clip image download failed with status: \(http.statusCode)")
                } else {
                    NSLog("o-clip image download failed: invalid response")
                }
                completion(nil)
                return
            }
            if let http = response as? HTTPURLResponse {
                oclipLog("image download HTTP ok status=\(http.statusCode) bytes=\(data.count) ref=\(imageRef.debugSummary)")
            }
            completion(RustImageInfo(
                width: imageRef.width,
                height: imageRef.height,
                bitsPerPixel: imageRef.bitsPerPixel,
                dataSize: data.count,
                format: imageRef.format,
                rawData: data.base64EncodedString()
            ))
        }.resume()
    }

    private func authorizedRequest(url: URL, method: String) -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = method
        if let password = config.password, !password.isEmpty {
            request.setValue("Bearer \(password)", forHTTPHeaderField: "Authorization")
        }
        return request
    }

    private func httpBaseURL() -> URL? {
        guard var components = URLComponents(string: config.serverURL) else { return nil }
        if components.scheme == "ws" {
            components.scheme = "http"
        } else if components.scheme == "wss" {
            components.scheme = "https"
        }
        if components.path == "/ws" {
            components.path = ""
        }
        return components.url
    }

    private func isSuccess(_ response: URLResponse?) -> Bool {
        guard let http = response as? HTTPURLResponse else { return false }
        return (200..<300).contains(http.statusCode)
    }

    private func uniqueDownloadURL(filename: String) -> URL {
        let directory = config.resolvedDownloadDirectory
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let safeName = filename.isEmpty ? "unnamed" : filename
        let original = directory.appendingPathComponent(safeName)
        if !FileManager.default.fileExists(atPath: original.path) {
            return original
        }

        let ext = original.pathExtension
        let stem = original.deletingPathExtension().lastPathComponent
        for index in 1..<1000 {
            let candidateName = ext.isEmpty ? "\(stem)_\(index)" : "\(stem)_\(index).\(ext)"
            let candidate = directory.appendingPathComponent(candidateName)
            if !FileManager.default.fileExists(atPath: candidate.path) {
                return candidate
            }
        }
        return directory.appendingPathComponent("\(stem)_\(UUID().uuidString)\(ext.isEmpty ? "" : ".\(ext)")")
    }

    private func mimeType(for url: URL) -> String {
        switch url.pathExtension.lowercased() {
        case "png": return "image/png"
        case "jpg", "jpeg": return "image/jpeg"
        case "gif": return "image/gif"
        case "bmp": return "image/bmp"
        case "webp": return "image/webp"
        case "tif", "tiff": return "image/tiff"
        case "pdf": return "application/pdf"
        case "txt", "md", "log": return "text/plain"
        case "json": return "application/json"
        case "zip": return "application/zip"
        case "docx": return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        default: return "application/octet-stream"
        }
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        if config.acceptInvalidCerts,
           let trust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}

final class KeyWindow: NSWindow {
    weak var keyDelegate: ClipboardWindowController?

    override func keyDown(with event: NSEvent) {
        if keyDelegate?.handleKey(event) == true { return }
        super.keyDown(with: event)
    }
}

private enum OClipStyle {
    static func symbol(_ name: String, pointSize: CGFloat = 14, weight: NSFont.Weight = .medium) -> NSImage? {
        if #available(macOS 11.0, *) {
            let config = NSImage.SymbolConfiguration(pointSize: pointSize, weight: weight)
            return NSImage(systemSymbolName: name, accessibilityDescription: nil)?.withSymbolConfiguration(config)
        }
        return nil
    }

    static func typeTitle(_ type: String) -> String {
        switch type {
        case "url": return "URL"
        case "files": return "Files"
        case "image": return "Image"
        default: return "Text"
        }
    }

    static func typeSymbol(_ type: String) -> String {
        switch type {
        case "url": return "link"
        case "files": return "folder"
        case "image": return "photo"
        default: return "text.alignleft"
        }
    }

    static func typeColor(_ type: String) -> NSColor {
        switch type {
        case "url": return .systemBlue
        case "files": return .systemOrange
        case "image": return .systemPurple
        default: return .systemGreen
        }
    }

    static func byteCount(_ value: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: value, countStyle: .file)
    }

    static func itemCount(_ value: Int) -> String {
        value == 1 ? "1 item" : "\(value) items"
    }
}

final class RoundedPaneView: NSView {
    var fillColor: NSColor {
        didSet { updateLayerColors() }
    }
    var borderColor: NSColor {
        didSet { updateLayerColors() }
    }
    var borderWidth: CGFloat {
        didSet { layer?.borderWidth = borderWidth }
    }
    var cornerRadius: CGFloat {
        didSet { layer?.cornerRadius = cornerRadius }
    }
    var shadowOpacity: Float {
        didSet { layer?.shadowOpacity = shadowOpacity }
    }

    init(
        fillColor: NSColor = .clear,
        borderColor: NSColor = .clear,
        cornerRadius: CGFloat = 10,
        borderWidth: CGFloat = 0,
        shadowOpacity: Float = 0
    ) {
        self.fillColor = fillColor
        self.borderColor = borderColor
        self.borderWidth = borderWidth
        self.cornerRadius = cornerRadius
        self.shadowOpacity = shadowOpacity
        super.init(frame: .zero)
        wantsLayer = true
        translatesAutoresizingMaskIntoConstraints = false
        layer?.cornerRadius = cornerRadius
        layer?.borderWidth = borderWidth
        layer?.shadowColor = NSColor.black.cgColor
        layer?.shadowOffset = NSSize(width: 0, height: -2)
        layer?.shadowRadius = 10
        layer?.shadowOpacity = shadowOpacity
        updateLayerColors()
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        updateLayerColors()
    }

    private func updateLayerColors() {
        layer?.backgroundColor = resolvedCGColor(fillColor)
        layer?.borderColor = resolvedCGColor(borderColor)
    }

    private func resolvedCGColor(_ color: NSColor) -> CGColor {
        var result = (color.usingColorSpace(.deviceRGB) ?? color).cgColor
        effectiveAppearance.performAsCurrentDrawingAppearance {
            result = (color.usingColorSpace(.deviceRGB) ?? color).cgColor
        }
        return result
    }
}

final class FlippedStackView: NSStackView {
    override var isFlipped: Bool { true }
}

final class ClipboardEntryRowView: NSView {
    let entryID: Int64
    var onSelect: ((ClipboardEntryRowView) -> Void)?
    var onCopy: (() -> Void)?
    var isSelected = false {
        didSet { updateSelectionState() }
    }

    private let iconBackground = RoundedPaneView(cornerRadius: 8)
    private let iconView = NSImageView()
    private let previewLabel = NSTextField(labelWithString: "")
    private let metadataLabel = NSTextField(labelWithString: "")
    private let pinIndicator = NSImageView()

    init(entry: ClipboardEntry) {
        self.entryID = entry.id
        super.init(frame: .zero)
        setup()
        configure(with: entry)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func configure(with entry: ClipboardEntry) {
        let tint = OClipStyle.typeColor(entry.contentType)
        iconBackground.fillColor = tint.withAlphaComponent(0.08)
        iconView.contentTintColor = tint.withAlphaComponent(0.88)
        iconView.image = OClipStyle.symbol(OClipStyle.typeSymbol(entry.contentType), pointSize: 14, weight: .medium)
        previewLabel.stringValue = entry.preview.isEmpty ? OClipStyle.typeTitle(entry.contentType) : entry.preview
        metadataLabel.stringValue = [
            OClipStyle.typeTitle(entry.contentType),
            OClipStyle.byteCount(entry.byteSize),
            relativeDate(entry.createdAt),
            entry.source
        ].filter { !$0.isEmpty }.joined(separator: "  ·  ")
        pinIndicator.isHidden = !entry.pinned
    }

    override func mouseDown(with event: NSEvent) {
        onSelect?(self)
        if event.clickCount >= 2 {
            onCopy?()
        }
    }

    private func setup() {
        wantsLayer = true
        layer?.cornerRadius = 10
        translatesAutoresizingMaskIntoConstraints = false

        iconBackground.addSubview(iconView)
        addSubview(iconBackground)
        addSubview(previewLabel)
        addSubview(metadataLabel)
        addSubview(pinIndicator)

        iconView.translatesAutoresizingMaskIntoConstraints = false
        iconView.imageScaling = .scaleProportionallyDown
        pinIndicator.translatesAutoresizingMaskIntoConstraints = false
        pinIndicator.image = OClipStyle.symbol("pin.fill", pointSize: 11, weight: .semibold)
        pinIndicator.contentTintColor = .tertiaryLabelColor

        previewLabel.font = .systemFont(ofSize: 13.5, weight: .regular)
        previewLabel.lineBreakMode = .byTruncatingTail
        previewLabel.maximumNumberOfLines = 1
        previewLabel.translatesAutoresizingMaskIntoConstraints = false
        previewLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

        metadataLabel.font = .systemFont(ofSize: 11)
        metadataLabel.textColor = .secondaryLabelColor
        metadataLabel.lineBreakMode = .byTruncatingTail
        metadataLabel.maximumNumberOfLines = 1
        metadataLabel.translatesAutoresizingMaskIntoConstraints = false
        metadataLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

        NSLayoutConstraint.activate([
            iconBackground.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 12),
            iconBackground.centerYAnchor.constraint(equalTo: centerYAnchor),
            iconBackground.widthAnchor.constraint(equalToConstant: 30),
            iconBackground.heightAnchor.constraint(equalToConstant: 30),

            iconView.centerXAnchor.constraint(equalTo: iconBackground.centerXAnchor),
            iconView.centerYAnchor.constraint(equalTo: iconBackground.centerYAnchor),
            iconView.widthAnchor.constraint(equalToConstant: 16),
            iconView.heightAnchor.constraint(equalToConstant: 16),

            previewLabel.leadingAnchor.constraint(equalTo: iconBackground.trailingAnchor, constant: 10),
            previewLabel.trailingAnchor.constraint(equalTo: pinIndicator.leadingAnchor, constant: -8),
            previewLabel.topAnchor.constraint(equalTo: topAnchor, constant: 11),

            metadataLabel.leadingAnchor.constraint(equalTo: previewLabel.leadingAnchor),
            metadataLabel.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -14),
            metadataLabel.topAnchor.constraint(equalTo: previewLabel.bottomAnchor, constant: 4),

            pinIndicator.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -12),
            pinIndicator.centerYAnchor.constraint(equalTo: centerYAnchor),
            pinIndicator.widthAnchor.constraint(equalToConstant: 13),
            pinIndicator.heightAnchor.constraint(equalToConstant: 13)
        ])
        updateSelectionState()
    }

    private func relativeDate(_ value: String) -> String {
        guard let date = ISO8601DateFormatter.oclip.date(from: value) else { return value }
        return RelativeDateTimeFormatter.oclip.localizedString(for: date, relativeTo: Date())
    }

    private func updateSelectionState() {
        let color = isSelected
            ? NSColor.controlAccentColor.withAlphaComponent(0.14)
            : NSColor.clear
        layer?.backgroundColor = resolvedCGColor(color)
        previewLabel.font = .systemFont(ofSize: 13.5, weight: isSelected ? .semibold : .regular)
    }

    private func resolvedCGColor(_ color: NSColor) -> CGColor {
        var result = (color.usingColorSpace(.deviceRGB) ?? color).cgColor
        effectiveAppearance.performAsCurrentDrawingAppearance {
            result = (color.usingColorSpace(.deviceRGB) ?? color).cgColor
        }
        return result
    }
}

final class LegacyClipboardWindowController: NSWindowController, NSSearchFieldDelegate, NSWindowDelegate {
    private let store: ClipboardStore
    private let sync: SyncCoordinator?
    private var entries: [ClipboardEntry] = []
    private var selectedEntryID: Int64?
    private var rowViews: [ClipboardEntryRowView] = []
    private let listScrollView = NSScrollView()
    private let listStack = FlippedStackView()
    private let searchField = NSSearchField()
    private let countLabel = NSTextField(labelWithString: "")
    private let typeLabel = NSTextField(labelWithString: "")
    private let metadataLabel = NSTextField(labelWithString: "")
    private let textView = NSTextView()
    private let textScrollView = NSScrollView()
    private let imageView = NSImageView()
    private let detailIconBackground = RoundedPaneView(cornerRadius: 9)
    private let detailIconView = NSImageView()
    private let copyButton = NSButton(title: "", target: nil, action: nil)
    private let deleteButton = NSButton(title: "", target: nil, action: nil)
    private let pinButton = NSButton(title: "", target: nil, action: nil)

    init(store: ClipboardStore, sync: SyncCoordinator? = nil) {
        self.store = store
        self.sync = sync
        let window = KeyWindow(
            contentRect: NSRect(x: 0, y: 0, width: 920, height: 580),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = appName
        window.minSize = NSSize(width: 760, height: 500)
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.isMovableByWindowBackground = true
        if #available(macOS 11.0, *) {
            window.toolbarStyle = .unifiedCompact
        }
        window.center()
        super.init(window: window)
        window.delegate = self
        buildUI(in: window)
        reload()
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func show() {
        reload()
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func reload() {
        let previousID = selectedEntryID
        do {
            entries = try store.list(query: searchField.stringValue)
            countLabel.stringValue = OClipStyle.itemCount(entries.count)
            if let previousID, entries.contains(where: { $0.id == previousID }) {
                selectedEntryID = previousID
            } else {
                selectedEntryID = entries.first?.id
            }
            renderListRows()
            updatePreview()
        } catch {
            showError("Failed to load clipboard history", message: error.localizedDescription)
        }
    }

    func windowDidResize(_ notification: Notification) {
    }

    func controlTextDidChange(_ obj: Notification) {
        reload()
    }

    func handleKey(_ event: NSEvent) -> Bool {
        let key = event.charactersIgnoringModifiers ?? ""
        let editor = searchField.currentEditor()
        let editingSearch = editor != nil && window?.firstResponder === editor

        if event.keyCode == 53 {
            if editingSearch, !searchField.stringValue.isEmpty {
                searchField.stringValue = ""
                reload()
            } else {
                window?.orderOut(nil)
            }
            return true
        }

        if event.keyCode == 126 {
            moveSelection(delta: -1)
            return true
        }
        if event.keyCode == 125 {
            moveSelection(delta: 1)
            return true
        }
        if event.keyCode == 36 {
            copySelectedToPasteboard(nil)
            return true
        }

        if editingSearch { return false }

        if key == "/" {
            window?.makeFirstResponder(searchField)
            return true
        }
        if key.lowercased() == "d" {
            deleteSelected(nil)
            return true
        }
        if key.lowercased() == "p" {
            togglePin(nil)
            return true
        }
        return false
    }

    @objc func copySelectedToPasteboard(_ sender: Any?) {
        guard let entry = selectedEntry else { return }
        if sync?.copyRemoteContentIfNeeded(entry) == true { return }
        do {
            try write(entry: entry, to: NSPasteboard.general)
        } catch {
            showError("Failed to copy item", message: error.localizedDescription)
        }
    }

    @objc func deleteSelected(_ sender: Any?) {
        guard let entry = selectedEntry else { return }
        do {
            try store.delete(id: entry.id)
            reload()
        } catch {
            showError("Failed to delete item", message: error.localizedDescription)
        }
    }

    @objc func togglePin(_ sender: Any?) {
        guard let entry = selectedEntry else { return }
        do {
            try store.togglePin(id: entry.id)
            reload()
        } catch {
            showError("Failed to update item", message: error.localizedDescription)
        }
    }

    private var selectedEntry: ClipboardEntry? {
        guard let selectedEntryID else { return nil }
        return entries.first { $0.id == selectedEntryID }
    }

    private func buildUI(in window: NSWindow) {
        let contentView = NSView()
        contentView.wantsLayer = true
        contentView.layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor
        window.contentView = contentView

        let toolbar = NSStackView()
        toolbar.orientation = .horizontal
        toolbar.alignment = .centerY
        toolbar.spacing = 10
        toolbar.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(toolbar)

        let titleStack = NSStackView()
        titleStack.orientation = .vertical
        titleStack.alignment = .leading
        titleStack.spacing = 1
        let appLabel = NSTextField(labelWithString: appName)
        appLabel.font = .systemFont(ofSize: 16, weight: .semibold)
        countLabel.font = .systemFont(ofSize: 11, weight: .medium)
        countLabel.textColor = .secondaryLabelColor
        titleStack.addArrangedSubview(appLabel)
        titleStack.addArrangedSubview(countLabel)
        titleStack.widthAnchor.constraint(greaterThanOrEqualToConstant: 84).isActive = true

        searchField.placeholderString = "Search history"
        searchField.delegate = self
        searchField.controlSize = .large
        searchField.translatesAutoresizingMaskIntoConstraints = false
        searchField.widthAnchor.constraint(greaterThanOrEqualToConstant: 260).isActive = true
        searchField.widthAnchor.constraint(lessThanOrEqualToConstant: 460).isActive = true

        configureToolbarButton(copyButton, symbolName: "doc.on.doc", fallbackTitle: "Copy", toolTip: "Copy", action: #selector(copySelectedToPasteboard(_:)))
        configureToolbarButton(deleteButton, symbolName: "trash", fallbackTitle: "Delete", toolTip: "Delete", action: #selector(deleteSelected(_:)))
        configureToolbarButton(pinButton, symbolName: "pin", fallbackTitle: "Pin", toolTip: "Pin", action: #selector(togglePin(_:)))

        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)

        let actions = NSStackView()
        actions.orientation = .horizontal
        actions.alignment = .centerY
        actions.spacing = 6
        actions.addArrangedSubview(copyButton)
        actions.addArrangedSubview(deleteButton)
        actions.addArrangedSubview(pinButton)

        toolbar.addArrangedSubview(titleStack)
        toolbar.addArrangedSubview(searchField)
        toolbar.addArrangedSubview(spacer)
        toolbar.addArrangedSubview(actions)

        let contentStack = NSStackView()
        contentStack.orientation = .horizontal
        contentStack.alignment = .height
        contentStack.distribution = .fill
        contentStack.spacing = 10
        contentStack.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(contentStack)

        let listPane = RoundedPaneView(
            fillColor: .controlBackgroundColor.withAlphaComponent(0.42),
            borderColor: .separatorColor.withAlphaComponent(0.18),
            cornerRadius: 14,
            borderWidth: 0.5,
            shadowOpacity: 0.06
        )
        listStack.orientation = .vertical
        listStack.alignment = .width
        listStack.spacing = 2
        listStack.edgeInsets = NSEdgeInsets(top: 8, left: 6, bottom: 8, right: 6)
        listStack.translatesAutoresizingMaskIntoConstraints = false
        listScrollView.documentView = listStack
        listScrollView.hasVerticalScroller = true
        listScrollView.hasHorizontalScroller = false
        listScrollView.autohidesScrollers = true
        listScrollView.drawsBackground = false
        listScrollView.borderType = .noBorder
        listScrollView.translatesAutoresizingMaskIntoConstraints = false
        listPane.addSubview(listScrollView)
        contentStack.addArrangedSubview(listPane)
        listPane.widthAnchor.constraint(equalToConstant: 370).isActive = true
        listPane.setContentCompressionResistancePriority(.required, for: .horizontal)

        let detailPane = RoundedPaneView(
            fillColor: .textBackgroundColor.withAlphaComponent(0.78),
            borderColor: .separatorColor.withAlphaComponent(0.18),
            cornerRadius: 14,
            borderWidth: 0.5,
            shadowOpacity: 0.06
        )
        detailPane.setContentHuggingPriority(.defaultLow, for: .horizontal)
        detailPane.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let detail = NSStackView()
        detail.orientation = .vertical
        detail.spacing = 12
        detail.edgeInsets = NSEdgeInsets(top: 18, left: 18, bottom: 18, right: 18)
        detail.translatesAutoresizingMaskIntoConstraints = false
        detailPane.addSubview(detail)
        contentStack.addArrangedSubview(detailPane)

        let header = NSStackView()
        header.orientation = .horizontal
        header.alignment = .centerY
        header.spacing = 12

        detailIconBackground.fillColor = .controlBackgroundColor
        detailIconBackground.borderColor = .clear
        detailIconBackground.borderWidth = 0
        detailIconBackground.addSubview(detailIconView)
        detailIconView.translatesAutoresizingMaskIntoConstraints = false
        detailIconView.imageScaling = .scaleProportionallyDown

        let headingStack = NSStackView()
        headingStack.orientation = .vertical
        headingStack.alignment = .leading
        headingStack.spacing = 2

        typeLabel.font = .systemFont(ofSize: 15, weight: .semibold)
        typeLabel.lineBreakMode = .byTruncatingTail
        metadataLabel.textColor = .secondaryLabelColor
        metadataLabel.font = .systemFont(ofSize: 12)
        metadataLabel.lineBreakMode = .byTruncatingTail
        metadataLabel.maximumNumberOfLines = 2
        headingStack.addArrangedSubview(typeLabel)
        headingStack.addArrangedSubview(metadataLabel)

        header.addArrangedSubview(detailIconBackground)
        header.addArrangedSubview(headingStack)
        detail.addArrangedSubview(header)

        let separator = RoundedPaneView(fillColor: .separatorColor.withAlphaComponent(0.18), cornerRadius: 0)
        detail.addArrangedSubview(separator)

        textView.isEditable = false
        textView.isRichText = false
        textView.font = .systemFont(ofSize: 13.5, weight: .regular)
        textView.textColor = .labelColor
        textView.drawsBackground = false
        textView.textContainerInset = NSSize(width: 12, height: 12)
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.autoresizingMask = [.width]
        textView.textContainer?.widthTracksTextView = true
        textScrollView.documentView = textView
        textScrollView.hasVerticalScroller = true
        textScrollView.autohidesScrollers = true
        textScrollView.drawsBackground = false
        textScrollView.borderType = .noBorder
        detail.addArrangedSubview(textScrollView)

        imageView.imageScaling = .scaleProportionallyUpOrDown
        imageView.isHidden = true
        imageView.wantsLayer = true
        imageView.layer?.cornerRadius = 9
        imageView.layer?.masksToBounds = true
        imageView.layer?.backgroundColor = NSColor.controlBackgroundColor.withAlphaComponent(0.65).cgColor
        detail.addArrangedSubview(imageView)

        NSLayoutConstraint.activate([
            toolbar.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 18),
            toolbar.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -18),
            toolbar.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 14),
            toolbar.heightAnchor.constraint(equalToConstant: 38),
            contentStack.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 18),
            contentStack.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -18),
            contentStack.topAnchor.constraint(equalTo: toolbar.bottomAnchor, constant: 10),
            contentStack.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -18),
            listScrollView.leadingAnchor.constraint(equalTo: listPane.leadingAnchor),
            listScrollView.trailingAnchor.constraint(equalTo: listPane.trailingAnchor),
            listScrollView.topAnchor.constraint(equalTo: listPane.topAnchor),
            listScrollView.bottomAnchor.constraint(equalTo: listPane.bottomAnchor),
            listStack.leadingAnchor.constraint(equalTo: listScrollView.contentView.leadingAnchor),
            listStack.trailingAnchor.constraint(equalTo: listScrollView.contentView.trailingAnchor),
            listStack.topAnchor.constraint(equalTo: listScrollView.contentView.topAnchor),
            listStack.widthAnchor.constraint(equalTo: listScrollView.contentView.widthAnchor),
            listStack.heightAnchor.constraint(greaterThanOrEqualTo: listScrollView.contentView.heightAnchor),
            detail.leadingAnchor.constraint(equalTo: detailPane.leadingAnchor),
            detail.trailingAnchor.constraint(equalTo: detailPane.trailingAnchor),
            detail.topAnchor.constraint(equalTo: detailPane.topAnchor),
            detail.bottomAnchor.constraint(equalTo: detailPane.bottomAnchor),
            detailIconBackground.widthAnchor.constraint(equalToConstant: 34),
            detailIconBackground.heightAnchor.constraint(equalToConstant: 34),
            detailIconView.centerXAnchor.constraint(equalTo: detailIconBackground.centerXAnchor),
            detailIconView.centerYAnchor.constraint(equalTo: detailIconBackground.centerYAnchor),
            detailIconView.widthAnchor.constraint(equalToConstant: 17),
            detailIconView.heightAnchor.constraint(equalToConstant: 17),
            separator.heightAnchor.constraint(equalToConstant: 1),
            textScrollView.heightAnchor.constraint(greaterThanOrEqualToConstant: 320),
            imageView.heightAnchor.constraint(greaterThanOrEqualToConstant: 320)
        ])
    }

    private func renderListRows() {
        rowViews.removeAll()
        for view in listStack.arrangedSubviews {
            listStack.removeArrangedSubview(view)
            view.removeFromSuperview()
        }

        for entry in entries {
            let row = ClipboardEntryRowView(entry: entry)
            row.onSelect = { [weak self] row in
                self?.selectEntry(id: row.entryID, scroll: false)
            }
            row.onCopy = { [weak self] in
                self?.copySelectedToPasteboard(nil)
            }
            row.heightAnchor.constraint(equalToConstant: 52).isActive = true
            listStack.addArrangedSubview(row)
            rowViews.append(row)
        }
        updateRowSelection()
    }

    private func selectEntry(id: Int64, scroll: Bool) {
        selectedEntryID = id
        updateRowSelection()
        updatePreview()
        if scroll, let row = rowViews.first(where: { $0.entryID == id }) {
            row.scrollToVisible(row.bounds)
        }
    }

    private func updateRowSelection() {
        for row in rowViews {
            row.isSelected = row.entryID == selectedEntryID
        }
    }

    private func configureToolbarButton(
        _ button: NSButton,
        symbolName: String,
        fallbackTitle: String,
        toolTip: String,
        action: Selector
    ) {
        button.target = self
        button.action = action
        button.toolTip = toolTip
        button.bezelStyle = .regularSquare
        button.isBordered = false
        button.imagePosition = .imageOnly
        button.setButtonType(.momentaryPushIn)
        button.contentTintColor = .secondaryLabelColor
        button.translatesAutoresizingMaskIntoConstraints = false
        if let image = OClipStyle.symbol(symbolName, pointSize: 14, weight: .semibold) {
            button.image = image
            button.title = ""
        } else {
            button.title = fallbackTitle
        }
        button.widthAnchor.constraint(equalToConstant: 30).isActive = true
        button.heightAnchor.constraint(equalToConstant: 30).isActive = true
    }

    private func updatePinButton(isPinned: Bool) {
        let title = isPinned ? "Unpin" : "Pin"
        pinButton.toolTip = title
        if let image = OClipStyle.symbol(isPinned ? "pin.slash" : "pin", pointSize: 14, weight: .semibold) {
            pinButton.image = image
            pinButton.title = ""
        } else {
            pinButton.title = title
        }
    }

    private func updatePreview() {
        guard let entry = selectedEntry else {
            copyButton.isEnabled = false
            deleteButton.isEnabled = false
            pinButton.isEnabled = false
            updatePinButton(isPinned: false)
            detailIconBackground.fillColor = .controlBackgroundColor
            detailIconBackground.borderColor = .separatorColor.withAlphaComponent(0.45)
            detailIconView.contentTintColor = .tertiaryLabelColor
            detailIconView.image = OClipStyle.symbol("tray", pointSize: 16, weight: .medium)
            typeLabel.stringValue = entries.isEmpty ? "No clips yet" : "No item selected"
            metadataLabel.stringValue = ""
            textView.string = ""
            imageView.image = nil
            imageView.isHidden = true
            textScrollView.isHidden = false
            return
        }

        copyButton.isEnabled = true
        deleteButton.isEnabled = true
        pinButton.isEnabled = true
        updatePinButton(isPinned: entry.pinned)

        let tint = OClipStyle.typeColor(entry.contentType)
        detailIconBackground.fillColor = tint.withAlphaComponent(0.13)
        detailIconBackground.borderColor = tint.withAlphaComponent(0.26)
        detailIconView.contentTintColor = tint
        detailIconView.image = OClipStyle.symbol(OClipStyle.typeSymbol(entry.contentType), pointSize: 16, weight: .semibold)

        typeLabel.stringValue = entry.pinned
            ? "\(OClipStyle.typeTitle(entry.contentType)) · Pinned"
            : OClipStyle.typeTitle(entry.contentType)
        metadataLabel.stringValue = "\(OClipStyle.byteCount(entry.byteSize))  •  \(displayDate(entry.createdAt))  •  \(entry.source)"

        if entry.contentType == "image", let data = imageData(from: entry.content), let image = NSImage(data: data) {
            imageView.image = image
            imageView.isHidden = false
            textScrollView.isHidden = true
        } else {
            imageView.isHidden = true
            textScrollView.isHidden = false
            textView.string = previewText(for: entry)
        }
    }

    private func moveSelection(delta: Int) {
        guard !entries.isEmpty else { return }
        let current = selectedEntryID.flatMap { id in entries.firstIndex(where: { $0.id == id }) } ?? 0
        let next = max(0, min(entries.count - 1, current + delta))
        selectEntry(id: entries[next].id, scroll: true)
    }

    private func write(entry: ClipboardEntry, to pasteboard: NSPasteboard) throws {
        try writeEntryToPasteboard(entry, pasteboard: pasteboard)
    }

    private func previewText(for entry: ClipboardEntry) -> String {
        guard let content = try? parseContent(entry.content) else { return entry.content }
        switch content {
        case .text(let text): return text
        case .url(let url): return url
        case .files(let paths): return paths.joined(separator: "\n")
        case .syncedFiles(let refs): return refs.map(\.filename).joined(separator: "\n")
        case .image, .syncedImage: return entry.preview
        }
    }

    private func parseContent(_ content: String) throws -> RustClipboardContent {
        try parseClipboardContent(content)
    }

    private func imageData(from content: String) -> Data? {
        guard let parsed = try? parseContent(content),
              case .image(let image) = parsed else { return nil }
        return pngData(from: image)
    }

    private func displayDate(_ value: String) -> String {
        if let date = ISO8601DateFormatter.oclip.date(from: value) {
            return DateFormatter.oclip.string(from: date)
        }
        return value
    }
}

final class ClipboardViewModel: ObservableObject {
    private let store: ClipboardStore
    private let sync: SyncCoordinator?
    @Published private(set) var entries: [ClipboardEntry] = []
    @Published var selectedID: Int64?
    @Published var searchText = ""
    @Published private(set) var focusSearchToken = 0
    var isSearchFocused = false
    var onShowConfig: (() -> Void)?

    init(store: ClipboardStore, sync: SyncCoordinator?) {
        self.store = store
        self.sync = sync
    }

    var selectedEntry: ClipboardEntry? {
        guard let selectedID else { return nil }
        return entries.first { $0.id == selectedID }
    }

    var canReconnect: Bool {
        sync?.canReconnect == true
    }

    func reload() {
        let previousID = selectedID
        do {
            entries = try store.list(query: searchText)
            if let previousID, entries.contains(where: { $0.id == previousID }) {
                selectedID = previousID
            } else {
                selectedID = entries.first?.id
            }
        } catch {
            showError("Failed to load clipboard history", message: error.localizedDescription)
        }
    }

    func searchChanged() {
        reload()
    }

    func clearSearch() {
        searchText = ""
        reload()
    }

    func focusSearch() {
        focusSearchToken += 1
    }

    func reconnect() {
        sync?.reconnect()
    }

    func showConfig() {
        onShowConfig?()
    }

    func select(_ entry: ClipboardEntry) {
        selectedID = entry.id
    }

    func copySelected() {
        guard let entry = selectedEntry else { return }
        if sync?.copyRemoteContentIfNeeded(entry) == true { return }
        do {
            try write(entry: entry, to: NSPasteboard.general)
        } catch {
            showError("Failed to copy item", message: error.localizedDescription)
        }
    }

    func deleteSelected() {
        guard let entry = selectedEntry else { return }
        do {
            try store.delete(id: entry.id)
            reload()
        } catch {
            showError("Failed to delete item", message: error.localizedDescription)
        }
    }

    func togglePin() {
        guard let entry = selectedEntry else { return }
        do {
            try store.togglePin(id: entry.id)
            reload()
        } catch {
            showError("Failed to update item", message: error.localizedDescription)
        }
    }

    func moveSelection(delta: Int) {
        guard !entries.isEmpty else { return }
        let current = selectedID.flatMap { id in entries.firstIndex(where: { $0.id == id }) } ?? 0
        let next = max(0, min(entries.count - 1, current + delta))
        selectedID = entries[next].id
    }

    func metadata(for entry: ClipboardEntry, relative: Bool) -> String {
        let date = relative ? relativeDate(entry.createdAt) : displayDate(entry.createdAt)
        return [OClipStyle.byteCount(entry.byteSize), date, entry.source]
            .filter { !$0.isEmpty }
            .joined(separator: "  ·  ")
    }

    func previewText(for entry: ClipboardEntry) -> String {
        guard let content = try? parseContent(entry.content) else { return entry.content }
        switch content {
        case .text(let text): return text
        case .url(let url): return url
        case .files(let paths): return paths.joined(separator: "\n")
        case .syncedFiles(let refs): return refs.map(\.filename).joined(separator: "\n")
        case .image, .syncedImage: return entry.preview
        }
    }

    func image(for entry: ClipboardEntry) -> NSImage? {
        guard entry.contentType == "image",
              let data = imageData(from: entry.content) else {
            return nil
        }
        return NSImage(data: data)
    }

    private func write(entry: ClipboardEntry, to pasteboard: NSPasteboard) throws {
        try writeEntryToPasteboard(entry, pasteboard: pasteboard)
    }

    private func parseContent(_ content: String) throws -> RustClipboardContent {
        try parseClipboardContent(content)
    }

    private func imageData(from content: String) -> Data? {
        guard let parsed = try? parseContent(content),
              case .image(let image) = parsed else { return nil }
        return pngData(from: image)
    }

    private func relativeDate(_ value: String) -> String {
        if let date = ISO8601DateFormatter.oclip.date(from: value) {
            return RelativeDateTimeFormatter.oclip.localizedString(for: date, relativeTo: Date())
        }
        return value
    }

    private func displayDate(_ value: String) -> String {
        if let date = ISO8601DateFormatter.oclip.date(from: value) {
            return DateFormatter.oclip.string(from: date)
        }
        return value
    }
}

private struct OClipRootView: View {
    @ObservedObject var model: ClipboardViewModel
    @FocusState private var searchFocused: Bool

    var body: some View {
        VStack(spacing: 12) {
            toolbar
            HStack(spacing: 12) {
                HistoryPane(model: model)
                    .frame(width: 356)
                PreviewPane(model: model)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .padding(.top, 14)
        .padding(.horizontal, 18)
        .padding(.bottom, 18)
        .frame(minWidth: 760, minHeight: 500)
        .background(Color(nsColor: .windowBackgroundColor))
        .onAppear { model.reload() }
        .onReceive(model.$focusSearchToken) { _ in searchFocused = true }
        .onReceive(Just(searchFocused)) { model.isSearchFocused = $0 }
    }

    private var toolbar: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 1) {
                Text(appName)
                    .font(.system(size: 16, weight: .semibold))
                Text(OClipStyle.itemCount(model.entries.count))
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(.secondary)
            }
            .frame(width: 88, alignment: .leading)

            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.secondary)
                TextField("Search history", text: $model.searchText)
                    .textFieldStyle(.plain)
                    .focused($searchFocused)
                    .onReceive(model.$searchText.dropFirst()) { _ in model.searchChanged() }
            }
            .padding(.horizontal, 10)
            .frame(maxWidth: 460, minHeight: 32)
            .background(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(Color(nsColor: .textBackgroundColor))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .stroke(searchFocused ? Color.accentColor.opacity(0.65) : Color(nsColor: .separatorColor).opacity(0.24), lineWidth: 1)
            )

            Spacer(minLength: 12)

            iconButton("arrow.clockwise", help: "Refresh", disabled: false) {
                model.reload()
            }
            iconButton("link", help: "Reconnect", disabled: !model.canReconnect) {
                model.reconnect()
            }
            iconButton("doc.on.doc", help: "Copy", disabled: model.selectedEntry == nil) {
                model.copySelected()
            }
            iconButton("trash", help: "Delete", disabled: model.selectedEntry == nil) {
                model.deleteSelected()
            }
            iconButton(model.selectedEntry?.pinned == true ? "pin.slash" : "pin", help: model.selectedEntry?.pinned == true ? "Unpin" : "Pin", disabled: model.selectedEntry == nil) {
                model.togglePin()
            }
            iconButton("gearshape", help: "Settings", disabled: false) {
                model.showConfig()
            }
        }
        .frame(height: 38)
    }

    private func iconButton(_ systemName: String, help: String, disabled: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: systemName)
                .font(.system(size: 14, weight: .medium))
                .foregroundColor(disabled ? .secondary.opacity(0.45) : .secondary)
                .frame(width: 30, height: 30)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(disabled)
        .help(help)
    }
}

private struct HistoryPane: View {
    @ObservedObject var model: ClipboardViewModel

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 2) {
                    ForEach(model.entries, id: \.id) { entry in
                        HistoryRow(entry: entry, selected: entry.id == model.selectedID, metadata: model.metadata(for: entry, relative: true))
                            .id(entry.id)
                            .onTapGesture {
                                model.select(entry)
                            }
                            .onTapGesture(count: 2) {
                                model.select(entry)
                                model.copySelected()
                            }
                    }
                }
                .padding(8)
            }
            .onReceive(model.$selectedID.compactMap { $0 }) { id in
                withAnimation(.easeOut(duration: 0.12)) {
                    proxy.scrollTo(id, anchor: .center)
                }
            }
        }
        .background(cardBackground(fill: Color(nsColor: .controlBackgroundColor).opacity(0.42)))
    }
}

private struct HistoryRow: View {
    let entry: ClipboardEntry
    let selected: Bool
    let metadata: String

    var body: some View {
        HStack(spacing: 10) {
            TypeIcon(contentType: entry.contentType, size: 30, symbolSize: 14)
            VStack(alignment: .leading, spacing: 4) {
                Text(entry.preview.isEmpty ? OClipStyle.typeTitle(entry.contentType) : entry.preview)
                    .font(.system(size: 13.5, weight: selected ? .semibold : .regular))
                    .lineLimit(1)
                    .truncationMode(.tail)
                Text("\(OClipStyle.typeTitle(entry.contentType))  ·  \(metadata)")
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            Spacer(minLength: 4)
            if entry.pinned {
                Image(systemName: "pin.fill")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundColor(.secondary)
            }
        }
        .padding(.horizontal, 10)
        .frame(height: 52)
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(selected ? Color.accentColor.opacity(0.14) : Color.clear)
        )
    }
}

private struct PreviewPane: View {
    @ObservedObject var model: ClipboardViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let entry = model.selectedEntry {
                header(for: entry)
                Divider()
                content(for: entry)
            } else {
                VStack(spacing: 8) {
                    Image(systemName: "tray")
                        .font(.system(size: 26, weight: .medium))
                        .foregroundColor(.secondary)
                    Text(model.entries.isEmpty ? "No clips yet" : "No item selected")
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .padding(18)
        .background(cardBackground(fill: Color(nsColor: .textBackgroundColor).opacity(0.78)))
    }

    private func header(for entry: ClipboardEntry) -> some View {
        HStack(spacing: 12) {
            TypeIcon(contentType: entry.contentType, size: 34, symbolSize: 16)
            VStack(alignment: .leading, spacing: 3) {
                Text(entry.pinned ? "\(OClipStyle.typeTitle(entry.contentType)) · Pinned" : OClipStyle.typeTitle(entry.contentType))
                    .font(.system(size: 15, weight: .semibold))
                    .lineLimit(1)
                Text(model.metadata(for: entry, relative: false))
                    .font(.system(size: 12))
                    .foregroundColor(.secondary)
                    .lineLimit(2)
                    .truncationMode(.tail)
            }
            Spacer(minLength: 0)
        }
    }

    @ViewBuilder
    private func content(for entry: ClipboardEntry) -> some View {
        if let image = model.image(for: entry) {
            GeometryReader { geometry in
                Image(nsImage: image)
                    .resizable()
                    .scaledToFit()
                    .frame(width: geometry.size.width, height: geometry.size.height)
                    .background(Color(nsColor: .controlBackgroundColor).opacity(0.45))
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            }
        } else {
            ScrollView {
                Text(model.previewText(for: entry))
                    .font(.system(size: 13.5, design: .monospaced))
                    .foregroundColor(.primary)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.top, 2)
            }
        }
    }
}

private struct TypeIcon: View {
    let contentType: String
    let size: CGFloat
    let symbolSize: CGFloat

    var body: some View {
        let color = Color(nsColor: OClipStyle.typeColor(contentType))
        Image(systemName: OClipStyle.typeSymbol(contentType))
            .font(.system(size: symbolSize, weight: .medium))
            .foregroundColor(color)
            .frame(width: size, height: size)
            .background(color.opacity(0.08))
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}

private func cardBackground(fill: Color) -> some View {
    RoundedRectangle(cornerRadius: 14, style: .continuous)
        .fill(fill)
        .overlay(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .stroke(Color(nsColor: .separatorColor).opacity(0.18), lineWidth: 0.5)
        )
        .shadow(color: Color.black.opacity(0.06), radius: 10, x: 0, y: 2)
}

final class ClipboardWindowController: NSWindowController {
    private let model: ClipboardViewModel

    init(store: ClipboardStore, sync: SyncCoordinator?, onShowConfig: @escaping () -> Void) {
        self.model = ClipboardViewModel(store: store, sync: sync)
        let window = KeyWindow(
            contentRect: NSRect(x: 0, y: 0, width: 920, height: 580),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = appName
        window.minSize = NSSize(width: 760, height: 500)
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.isMovableByWindowBackground = true
        if #available(macOS 11.0, *) {
            window.toolbarStyle = .unifiedCompact
        }
        window.center()
        super.init(window: window)
        model.onShowConfig = onShowConfig
        window.keyDelegate = self

        let hostingView = NSHostingView(rootView: OClipRootView(model: model))
        window.contentView = hostingView
        model.reload()
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func show() {
        reload()
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func reload() {
        model.reload()
    }

    func handleKey(_ event: NSEvent) -> Bool {
        let key = event.charactersIgnoringModifiers ?? ""

        if event.keyCode == 53 {
            if !model.searchText.isEmpty {
                model.clearSearch()
            } else {
                window?.orderOut(nil)
            }
            return true
        }

        if event.keyCode == 126 {
            model.moveSelection(delta: -1)
            return true
        }
        if event.keyCode == 125 {
            model.moveSelection(delta: 1)
            return true
        }
        if event.keyCode == 36 {
            model.copySelected()
            return true
        }

        if model.isSearchFocused { return false }

        if key == "/" {
            model.focusSearch()
            return true
        }
        if key.lowercased() == "d" {
            model.deleteSelected()
            return true
        }
        if key.lowercased() == "p" {
            model.togglePin()
            return true
        }
        return false
    }
}

enum CopyError: LocalizedError {
    case unsupported
    case remoteContentRequiresSync

    var errorDescription: String? {
        switch self {
        case .unsupported:
            return "Unsupported clipboard content"
        case .remoteContentRequiresSync:
            return "Remote content must be downloaded before copying"
        }
    }
}

private func writeEntryToPasteboard(_ entry: ClipboardEntry, pasteboard: NSPasteboard = .general) throws {
    let content = try parseClipboardContent(entry.content)
    try writeContentToPasteboard(content, pasteboard: pasteboard)
}

private func writeContentToPasteboard(_ content: RustClipboardContent, pasteboard: NSPasteboard = .general) throws {
    oclipLog("pasteboard write starting \(content.debugSummary)")
    pasteboard.clearContents()

    switch content {
    case .text(let text):
        pasteboard.declareTypes([.string, selfWriteType], owner: nil)
        pasteboard.setString(text, forType: .string)
        pasteboard.setString("1", forType: selfWriteType)
        oclipLog("pasteboard write text ok chars=\(text.count)")
    case .url(let url):
        pasteboard.declareTypes([.URL, .string, selfWriteType], owner: nil)
        pasteboard.setString(url, forType: .URL)
        pasteboard.setString(url, forType: .string)
        pasteboard.setString("1", forType: selfWriteType)
        oclipLog("pasteboard write url ok chars=\(url.count)")
    case .files(let paths):
        let urls = paths.map { NSURL(fileURLWithPath: $0) }
        guard !urls.isEmpty, pasteboard.writeObjects(urls) else {
            oclipLog("pasteboard write files failed paths=[\(debugFilePaths(paths))]")
            throw CopyError.unsupported
        }
        pasteboard.setString("1", forType: selfWriteType)
        oclipLog("pasteboard write files ok paths=[\(debugFilePaths(paths))] types=[\(pasteboard.types?.map(\.rawValue).joined(separator: ", ") ?? "")]")
    case .image(let image):
        guard let png = pngData(from: image) else {
            oclipLog("pasteboard write image failed to build PNG \(image.debugSummary)")
            throw CopyError.unsupported
        }
        pasteboard.declareTypes([.png, .tiff, selfWriteType], owner: nil)
        let pngOk = pasteboard.setData(png, forType: .png)
        var tiffBytes = 0
        var tiffOk = false
        if let tiff = NSImage(data: png)?.tiffRepresentation {
            tiffBytes = tiff.count
            tiffOk = pasteboard.setData(tiff, forType: .tiff)
        }
        pasteboard.setString("1", forType: selfWriteType)
        oclipLog("pasteboard write image pngOk=\(pngOk) pngBytes=\(png.count) tiffOk=\(tiffOk) tiffBytes=\(tiffBytes) types=[\(pasteboard.types?.map(\.rawValue).joined(separator: ", ") ?? "")]")
    case .syncedFiles, .syncedImage:
        oclipLog("pasteboard write rejected synced content without download \(content.debugSummary)")
        throw CopyError.remoteContentRequiresSync
    }
}

private func parseClipboardContent(_ content: String) throws -> RustClipboardContent {
    guard let data = content.data(using: .utf8) else {
        throw CopyError.unsupported
    }
    return try jsonDecoder.decode(RustClipboardContent.self, from: data)
}

private func pngData(from image: RustImageInfo) -> Data? {
    guard let raw = image.rawData,
          let data = Data(base64Encoded: raw) else {
        return nil
    }

    if image.format == "Png" {
        return data
    }

    if let png = pngDataFromDIB32(data) {
        return png
    }

    if let bmp = bmpFileData(fromDib: data),
       let bitmap = NSBitmapImageRep(data: bmp),
       let png = bitmap.representation(using: .png, properties: [:]) {
        return png
    }

    return pngDataFromDIB32(data)
}

private func bmpFileData(fromDib dib: Data) -> Data? {
    guard dib.count >= 4 else { return nil }
    let headerSize = UInt32(dib[0]) |
        (UInt32(dib[1]) << 8) |
        (UInt32(dib[2]) << 16) |
        (UInt32(dib[3]) << 24)
    let fileSize = UInt32(14 + dib.count)
    let pixelOffset = UInt32(14) + headerSize

    var bmp = Data()
    bmp.append(0x42)
    bmp.append(0x4d)
    bmp.appendUInt32LE(fileSize)
    bmp.appendUInt32LE(0)
    bmp.appendUInt32LE(pixelOffset)
    bmp.append(dib)
    return bmp
}

private func pngDataFromDIB32(_ dib: Data) -> Data? {
    guard let headerSizeValue = uint32LE(dib, at: 0) else { return nil }
    let headerSize = Int(headerSizeValue)
    guard headerSize >= 40,
          dib.count >= headerSize,
          let dibWidth = int32LE(dib, at: 4),
          let dibHeight = int32LE(dib, at: 8),
          let planes = uint16LE(dib, at: 12),
          let bitCount = uint16LE(dib, at: 14),
          let compression = uint32LE(dib, at: 16),
          planes == 1 else {
        return nil
    }

    let width = Int(dibWidth)
    let height = Int(dibHeight < 0 ? -dibHeight : dibHeight)
    guard width > 0,
          height > 0,
          width <= 100_000,
          height <= 100_000,
          bitCount == 32,
          compression == 0 || compression == 3 else {
        return nil
    }

    var redMask: UInt32 = 0x00ff0000
    var greenMask: UInt32 = 0x0000ff00
    var blueMask: UInt32 = 0x000000ff
    var alphaMask: UInt32 = 0xff000000
    var pixelOffset = headerSize

    if compression == 3 {
        if headerSize >= 56 {
            redMask = uint32LE(dib, at: 40) ?? redMask
            greenMask = uint32LE(dib, at: 44) ?? greenMask
            blueMask = uint32LE(dib, at: 48) ?? blueMask
            alphaMask = uint32LE(dib, at: 52) ?? alphaMask
        } else if dib.count >= headerSize + 12 {
            redMask = uint32LE(dib, at: headerSize) ?? redMask
            greenMask = uint32LE(dib, at: headerSize + 4) ?? greenMask
            blueMask = uint32LE(dib, at: headerSize + 8) ?? blueMask
            alphaMask = 0
            pixelOffset = headerSize + 12
            if dib.count >= headerSize + 16 {
                alphaMask = uint32LE(dib, at: headerSize + 12) ?? 0
                pixelOffset = headerSize + 16
            }
        }
    } else if headerSize >= 56,
              let red = uint32LE(dib, at: 40),
              let green = uint32LE(dib, at: 44),
              let blue = uint32LE(dib, at: 48),
              red != 0,
              green != 0,
              blue != 0 {
        redMask = red
        greenMask = green
        blueMask = blue
        alphaMask = uint32LE(dib, at: 52) ?? alphaMask
    }

    let bytesPerRow = width * 4
    guard pixelOffset >= 0,
          dib.count >= pixelOffset + (bytesPerRow * height) else {
        return nil
    }

    let bottomUp = dibHeight > 0
    var rgba = [UInt8](repeating: 0, count: bytesPerRow * height)
    var hasNonZeroAlpha = false

    for y in 0..<height {
        let sourceY = bottomUp ? (height - 1 - y) : y
        let sourceBase = pixelOffset + sourceY * bytesPerRow
        let destBase = y * bytesPerRow
        for x in 0..<width {
            guard let pixel = uint32LE(dib, at: sourceBase + x * 4) else { return nil }
            let dest = destBase + x * 4
            rgba[dest] = maskedChannel(pixel, mask: redMask, defaultValue: 0)
            rgba[dest + 1] = maskedChannel(pixel, mask: greenMask, defaultValue: 0)
            rgba[dest + 2] = maskedChannel(pixel, mask: blueMask, defaultValue: 0)
            rgba[dest + 3] = maskedChannel(pixel, mask: alphaMask, defaultValue: 255)
            if rgba[dest + 3] != 0 {
                hasNonZeroAlpha = true
            }
        }
    }

    if alphaMask != 0, !hasNonZeroAlpha {
        for index in stride(from: 3, to: rgba.count, by: 4) {
            rgba[index] = 255
        }
    }

    return pngDataFromRGBA(rgba, width: width, height: height)
}

private func pngDataFromRGBA(_ rgba: [UInt8], width: Int, height: Int) -> Data? {
    guard let bitmap = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: width,
        pixelsHigh: height,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .deviceRGB,
        bytesPerRow: width * 4,
        bitsPerPixel: 32
    ),
    let destination = bitmap.bitmapData else {
        return nil
    }

    rgba.withUnsafeBytes { source in
        if let base = source.baseAddress {
            memcpy(destination, base, rgba.count)
        }
    }
    return bitmap.representation(using: .png, properties: [:])
}

private func maskedChannel(_ pixel: UInt32, mask: UInt32, defaultValue: UInt8) -> UInt8 {
    guard mask != 0 else { return defaultValue }
    let shift = mask.trailingZeroBitCount
    let bits = 32 - mask.leadingZeroBitCount - shift
    guard bits > 0 else { return defaultValue }
    let value = (pixel & mask) >> shift
    if bits >= 8 {
        return UInt8(truncatingIfNeeded: value >> (bits - 8))
    }
    let maxValue = (UInt32(1) << bits) - 1
    return UInt8((value * 255) / maxValue)
}

private func uint16LE(_ data: Data, at offset: Int) -> UInt16? {
    guard offset >= 0, offset + 2 <= data.count else { return nil }
    return UInt16(data[offset]) | (UInt16(data[offset + 1]) << 8)
}

private func uint32LE(_ data: Data, at offset: Int) -> UInt32? {
    guard offset >= 0, offset + 4 <= data.count else { return nil }
    return UInt32(data[offset]) |
        (UInt32(data[offset + 1]) << 8) |
        (UInt32(data[offset + 2]) << 16) |
        (UInt32(data[offset + 3]) << 24)
}

private func int32LE(_ data: Data, at offset: Int) -> Int32? {
    guard let unsigned = uint32LE(data, at: offset) else { return nil }
    return Int32(bitPattern: unsigned)
}

private enum ConfigSaveError: LocalizedError {
    case invalidInteger(label: String)

    var errorDescription: String? {
        switch self {
        case .invalidInteger(let label):
            return "\(label) must be a positive integer."
        }
    }
}

final class ConfigViewModel: ObservableObject {
    @Published var serverURL = ""
    @Published var password = ""
    @Published var autoConnect = true
    @Published var acceptInvalidCerts = false
    @Published var maxSyncSize = ""
    @Published var maxFileSyncSize = ""
    @Published var imageInlineThreshold = ""
    @Published var downloadDir = ""
    @Published var maxEntries = ""
    @Published var dbPath = ""
    @Published var statusText = ""

    var configPath: String {
        AppConfig.configURL.path
    }

    init() {
        reload()
    }

    func reload() {
        let config = AppConfig.load()
        serverURL = config.serverURL
        password = config.password ?? ""
        autoConnect = config.autoConnect
        acceptInvalidCerts = config.acceptInvalidCerts
        maxSyncSize = String(config.maxSyncSize)
        maxFileSyncSize = String(config.maxFileSyncSize)
        imageInlineThreshold = String(config.imageInlineThreshold)
        downloadDir = config.downloadDir
        maxEntries = String(config.maxEntries)
        dbPath = config.dbPath
        statusText = ""
    }

    func save() {
        do {
            let config = try buildConfig()
            try config.write()
            statusText = "Saved. Restart O-Clip to apply connection and storage changes."
        } catch {
            statusText = error.localizedDescription
            showError("Failed to save settings", message: error.localizedDescription)
        }
    }

    private func buildConfig() throws -> AppConfig {
        var config = AppConfig()
        config.serverURL = serverURL.trimmingCharacters(in: .whitespacesAndNewlines)
        config.password = password.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : password
        config.autoConnect = autoConnect
        config.acceptInvalidCerts = acceptInvalidCerts
        config.maxSyncSize = try positiveInt("Max sync size", maxSyncSize)
        config.maxFileSyncSize = try positiveInt("Max file sync size", maxFileSyncSize)
        config.imageInlineThreshold = try positiveInt("Image inline threshold", imageInlineThreshold)
        config.downloadDir = downloadDir.trimmingCharacters(in: .whitespacesAndNewlines)
        config.maxEntries = try positiveInt("Max entries", maxEntries)
        config.dbPath = dbPath.trimmingCharacters(in: .whitespacesAndNewlines)
        return config
    }

    private func positiveInt(_ label: String, _ value: String) throws -> Int {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let intValue = Int(trimmed), intValue > 0 else {
            throw ConfigSaveError.invalidInteger(label: label)
        }
        return intValue
    }
}

private struct ConfigRootView: View {
    @ObservedObject var model: ConfigViewModel
    let onClose: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section("Server") {
                    TextField("URL", text: $model.serverURL)
                    SecureField("Password", text: $model.password)
                    Toggle("Auto-connect", isOn: $model.autoConnect)
                    Toggle("Accept invalid certificates", isOn: $model.acceptInvalidCerts)
                    TextField("Max sync size", text: $model.maxSyncSize)
                    TextField("Max file sync size", text: $model.maxFileSyncSize)
                    TextField("Image inline threshold", text: $model.imageInlineThreshold)
                    HStack {
                        TextField("Download directory", text: $model.downloadDir)
                        Button {
                            chooseDownloadDirectory()
                        } label: {
                            Image(systemName: "folder")
                        }
                        .buttonStyle(.borderless)
                        .help("Choose download directory")
                    }
                }

                Section("Storage") {
                    TextField("Max entries", text: $model.maxEntries)
                    TextField("Database path", text: $model.dbPath)
                }
            }
            .formStyle(.grouped)

            Divider()

            HStack(spacing: 10) {
                Text(model.configPath)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: 12)
                if !model.statusText.isEmpty {
                    Text(model.statusText)
                        .font(.caption)
                        .foregroundColor(model.statusText.hasPrefix("Saved") ? .secondary : .red)
                        .lineLimit(1)
                }
                Button("Reload") {
                    model.reload()
                }
                Button("Cancel") {
                    onClose()
                }
                Button("Save") {
                    model.save()
                }
                .keyboardShortcut(.defaultAction)
            }
            .padding(14)
        }
        .frame(width: 640, height: 560)
    }

    private func chooseDownloadDirectory() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.canCreateDirectories = true
        if !model.downloadDir.isEmpty {
            panel.directoryURL = URL(fileURLWithPath: NSString(string: model.downloadDir).expandingTildeInPath)
        }
        if panel.runModal() == .OK, let url = panel.url {
            model.downloadDir = url.path
        }
    }
}

final class ConfigWindowController: NSWindowController {
    private let model = ConfigViewModel()

    init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 640, height: 560),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Settings"
        window.center()
        super.init(window: window)
        window.contentView = NSHostingView(rootView: ConfigRootView(model: model) { [weak window] in
            window?.orderOut(nil)
        })
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func show() {
        model.reload()
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private var store: ClipboardStore?
    private var monitor: ClipboardMonitor?
    private var windowController: ClipboardWindowController?
    private var syncCoordinator: SyncCoordinator?
    private var configWindowController: ConfigWindowController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        installMainMenu()

        do {
            let config = AppConfig.load()
            let store = try ClipboardStore(path: config.databaseURL)
            self.store = store
            let sync = SyncCoordinator(config: config, store: store)
            self.syncCoordinator = sync
            let controller = ClipboardWindowController(store: store, sync: sync) { [weak self] in
                self?.showConfigWindow(nil)
            }
            self.windowController = controller
            sync.onChange = { [weak controller] in controller?.reload() }
            let monitor = ClipboardMonitor(store: store, config: config)
            monitor.onChange = { [weak controller] in controller?.reload() }
            monitor.onCapture = { [weak sync] captured, noCloud in
                sync?.handleLocalCapture(captured, noCloud: noCloud)
            }
            monitor.shouldSkipCapture = { [weak sync] captured in
                sync?.shouldSkipLocalCapture(captured) ?? false
            }
            monitor.onExternalPlaceholderInterference = { [weak sync] in
                sync?.restoreAfterExternalPlaceholder()
            }
            monitor.start()
            self.monitor = monitor
            sync.start()
            installStatusItem()
        } catch {
            showError("Failed to start O-Clip", message: error.localizedDescription)
            NSApp.terminate(nil)
        }
    }

    @objc private func toggleWindow(_ sender: Any?) {
        if NSApp.currentEvent?.type == .rightMouseUp {
            showStatusMenu()
            return
        }

        guard let window = windowController?.window else {
            windowController?.show()
            return
        }
        if window.isVisible, window.isKeyWindow {
            window.orderOut(nil)
        } else {
            windowController?.show()
        }
    }

    @objc private func showWindow(_ sender: Any?) {
        windowController?.show()
    }

    @objc private func showConfigWindow(_ sender: Any?) {
        if configWindowController == nil {
            configWindowController = ConfigWindowController()
        }
        configWindowController?.show()
    }

    @objc private func quit(_ sender: Any?) {
        NSApp.terminate(nil)
    }

    private func installStatusItem() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let image = OClipStyle.symbol("doc.on.clipboard", pointSize: 15, weight: .medium) {
            item.button?.image = image
            item.button?.imagePosition = .imageOnly
        } else {
            item.button?.title = "O-Clip"
        }
        item.button?.toolTip = appName
        item.button?.target = self
        item.button?.action = #selector(toggleWindow(_:))
        item.button?.sendAction(on: [.leftMouseUp, .rightMouseUp])
        statusItem = item
    }

    private func showStatusMenu() {
        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "Open O-Clip", action: #selector(showWindow(_:)), keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "Settings...", action: #selector(showConfigWindow(_:)), keyEquivalent: ","))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Quit", action: #selector(quit(_:)), keyEquivalent: "q"))
        menu.items.forEach { $0.target = self }
        statusItem?.menu = menu
        statusItem?.button?.performClick(nil)
        statusItem?.menu = nil
    }

    private func installMainMenu() {
        let mainMenu = NSMenu()
        let appMenuItem = NSMenuItem()
        let appMenu = NSMenu(title: appName)
        let settingsItem = NSMenuItem(title: "Settings...", action: #selector(showConfigWindow(_:)), keyEquivalent: ",")
        settingsItem.target = self
        appMenu.addItem(settingsItem)
        appMenu.addItem(NSMenuItem.separator())
        let quitItem = NSMenuItem(title: "Quit O-Clip", action: #selector(quit(_:)), keyEquivalent: "q")
        quitItem.target = self
        appMenu.addItem(quitItem)
        appMenuItem.submenu = appMenu
        mainMenu.addItem(appMenuItem)
        NSApp.mainMenu = mainMenu
    }
}

private func showError(_ title: String, message: String) {
    NSApp.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    alert.messageText = title
    alert.informativeText = message
    alert.alertStyle = .warning
    alert.runModal()
}


private func rgbaBytes(from image: RustImageInfo) -> Data? {
    guard let png = pngData(from: image) else { return nil }
    return rgbaBytes(fromPNG: png)
}

private func rgbaBytes(fromPNG data: Data) -> Data? {
    guard let source = NSBitmapImageRep(data: data),
          let bitmap = NSBitmapImageRep(
            bitmapDataPlanes: nil,
            pixelsWide: source.pixelsWide,
            pixelsHigh: source.pixelsHigh,
            bitsPerSample: 8,
            samplesPerPixel: 4,
            hasAlpha: true,
            isPlanar: false,
            colorSpaceName: .deviceRGB,
            bytesPerRow: source.pixelsWide * 4,
            bitsPerPixel: 32
          ) else { return nil }

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
    NSImage(data: data)?.draw(in: NSRect(x: 0, y: 0, width: source.pixelsWide, height: source.pixelsHigh))
    NSGraphicsContext.restoreGraphicsState()

    guard let pointer = bitmap.bitmapData else { return nil }
    return Data(bytes: pointer, count: bitmap.bytesPerRow * bitmap.pixelsHigh)
}

extension Data {
    mutating func appendString(_ value: String) {
        append(value.data(using: .utf8) ?? Data())
    }

    mutating func appendUInt32LE(_ value: UInt32) {
        var little = value.littleEndian
        Swift.withUnsafeBytes(of: &little) { append(contentsOf: $0) }
    }
}

extension ISO8601DateFormatter {
    static let oclip: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()
}

extension DateFormatter {
    static let oclip: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .medium
        return formatter
    }()
}

extension RelativeDateTimeFormatter {
    static let oclip: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter
    }()
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
