import AppKit
import CryptoKit
import Foundation
import SQLite3

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

enum RustClipboardContent: Codable {
    case text(String)
    case url(String)
    case files([String])
    case image(RustImageInfo)

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let object = try container.decode([String: Payload].self)
        if let value = object["Text"]?.string {
            self = .text(value)
        } else if let value = object["Url"]?.string {
            self = .url(value)
        } else if let value = object["Files"]?.strings {
            self = .files(value)
        } else if let value = object["Image"]?.image {
            self = .image(value)
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
        case .image(let value):
            try container.encode(["Image": Payload.image(value)])
        }
    }

    enum Payload: Codable {
        case string(String)
        case strings([String])
        case image(RustImageInfo)

        var string: String? {
            if case .string(let value) = self { return value }
            return nil
        }

        var strings: [String]? {
            if case .strings(let value) = self { return value }
            return nil
        }

        var image: RustImageInfo? {
            if case .image(let value) = self { return value }
            return nil
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let value = try? container.decode(String.self) {
                self = .string(value)
            } else if let value = try? container.decode([String].self) {
                self = .strings(value)
            } else {
                self = .image(try container.decode(RustImageInfo.self))
            }
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .string(let value):
                try container.encode(value)
            case .strings(let value):
                try container.encode(value)
            case .image(let value):
                try container.encode(value)
            }
        }
    }
}

struct AppConfig {
    var maxEntries: Int = 10_000
    var dbPath: String = ""
    var serverURL: String = ""

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
            let line = String(rawLine.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0])
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
            }
        }
        return config
    }

    private static func writeDefault(to url: URL) {
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let body = """
        [server]
        url = ""
        auto_connect = true
        max_sync_size = 5242880
        accept_invalid_certs = false
        max_file_sync_size = 52428800
        download_dir = ""
        image_inline_threshold = 204800

        [storage]
        max_entries = 10000
        db_path = ""
        """
        try? body.write(to: url, atomically: true, encoding: .utf8)
    }

    private static func parseTomlValue(_ value: String) -> String {
        var result = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if let comment = result.firstIndex(of: "#") {
            result = String(result[..<comment]).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        if result.hasPrefix("\""), result.hasSuffix("\""), result.count >= 2 {
            result = String(result.dropFirst().dropLast())
                .replacingOccurrences(of: "\\\"", with: "\"")
                .replacingOccurrences(of: "\\n", with: "\n")
                .replacingOccurrences(of: "\\\\", with: "\\")
        }
        return result
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

    func delete(id: Int64) throws {
        try statement(sql: "DELETE FROM entries WHERE id = ?1") { stmt in
            sqlite3_bind_int64(stmt, 1, id)
            guard sqlite3_step(stmt) == SQLITE_DONE else { throw StoreError.query(message: lastError) }
        }
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

    var contentType: String {
        switch self {
        case .text: return "text"
        case .url: return "url"
        case .files: return "files"
        case .image: return "image"
        }
    }

    var contentJSON: String {
        let content: RustClipboardContent
        switch self {
        case .text(let text):
            content = .text(text)
        case .url(let url):
            content = .url(url)
        case .files(let paths):
            content = .files(paths)
        case .image(let data, let width, let height, let bitsPerPixel):
            content = .image(RustImageInfo(
                width: width,
                height: height,
                bitsPerPixel: bitsPerPixel,
                dataSize: data.count,
                format: "Png",
                rawData: data.base64EncodedString()
            ))
        }
        guard let data = try? jsonEncoder.encode(content) else { return "{}" }
        return String(data: data, encoding: .utf8) ?? "{}"
    }

    var preview: String {
        switch self {
        case .text(let text):
            return clipped(text.components(separatedBy: .newlines).first ?? text)
        case .url(let url):
            return clipped(url)
        case .files(let paths):
            if paths.count == 1 {
                return URL(fileURLWithPath: paths[0]).lastPathComponent.isEmpty ? paths[0] : URL(fileURLWithPath: paths[0]).lastPathComponent
            }
            return "\(paths.count) files"
        case .image(_, let width, let height, _):
            return "\(width)x\(height) Png"
        }
    }

    var byteSize: Int {
        switch self {
        case .text(let text): return text.utf8.count
        case .url(let url): return url.utf8.count
        case .files(let paths): return paths.reduce(0) { $0 + $1.utf8.count }
        case .image(let data, _, _, _): return data.count
        }
    }

    var hash: String {
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
        case .image(let png, let width, let height, _):
            data.appendString("image:")
            data.appendUInt32LE(UInt32(width))
            data.appendUInt32LE(UInt32(height))
            if let rgba = rgbaBytes(fromPNG: png) {
                data.append(rgba)
            } else {
                data.append(png)
            }
        }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }


    private static func clipped(_ value: String) -> String {
        if value.count <= 120 { return value }
        let index = value.index(value.startIndex, offsetBy: 120)
        return String(value[..<index]) + "..."
    }
}

final class ClipboardMonitor {
    private let store: ClipboardStore
    private let config: AppConfig
    private var timer: Timer?
    private var lastChangeCount = NSPasteboard.general.changeCount
    var onChange: (() -> Void)?

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
        if rawTypes.contains(selfWriteType.rawValue) { return }
        if shouldIgnore(types: rawTypes) { return }

        let isTransient = rawTypes.contains { $0.contains("TransientType") }
        guard let captured = capture(from: pasteboard) else { return }
        do {
            try store.insert(captured, maxEntries: config.maxEntries, synced: isTransient)
            onChange?()
        } catch {
            showError("Failed to save clipboard item", message: error.localizedDescription)
        }
    }

    private func shouldIgnore(types: [String]) -> Bool {
        types.contains { type in
            type.contains("ConcealedType") || type.contains("AutoGeneratedType") || type.contains("OneTimeCode")
        }
    }

    private func capture(from pasteboard: NSPasteboard) -> CapturedClipboard? {
        if let objects = pasteboard.readObjects(
            forClasses: [NSURL.self],
            options: [.urlReadingFileURLsOnly: true]
        ) as? [NSURL] {
            let paths = objects.map { $0.path ?? $0.absoluteString ?? "" }.filter { !$0.isEmpty }
            if !paths.isEmpty { return .files(paths) }
        }

        if let png = pasteboard.data(forType: .png), let image = NSBitmapImageRep(data: png) {
            let bits = image.bitsPerPixel == 0 ? 32 : image.bitsPerPixel
            return .image(data: png, width: image.pixelsWide, height: image.pixelsHigh, bitsPerPixel: bits)
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
}

final class KeyWindow: NSWindow {
    weak var keyDelegate: ClipboardWindowController?

    override func keyDown(with event: NSEvent) {
        if keyDelegate?.handleKey(event) == true { return }
        super.keyDown(with: event)
    }
}

final class ClipboardWindowController: NSWindowController, NSTableViewDataSource, NSTableViewDelegate, NSSearchFieldDelegate {
    private let store: ClipboardStore
    private var entries: [ClipboardEntry] = []
    private let tableView = NSTableView()
    private let searchField = NSSearchField()
    private let typeLabel = NSTextField(labelWithString: "")
    private let metadataLabel = NSTextField(labelWithString: "")
    private let textView = NSTextView()
    private let imageView = NSImageView()
    private let pinButton = NSButton(title: "Pin", target: nil, action: nil)

    init(store: ClipboardStore) {
        self.store = store
        let window = KeyWindow(
            contentRect: NSRect(x: 0, y: 0, width: 920, height: 580),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = appName
        window.center()
        super.init(window: window)
        window.keyDelegate = self
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
        let selectedID = selectedEntry?.id
        do {
            entries = try store.list(query: searchField.stringValue)
            tableView.reloadData()
            if let selectedID, let index = entries.firstIndex(where: { $0.id == selectedID }) {
                tableView.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
            } else if !entries.isEmpty, tableView.selectedRow < 0 {
                tableView.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
            }
            updatePreview()
        } catch {
            showError("Failed to load clipboard history", message: error.localizedDescription)
        }
    }

    func numberOfRows(in tableView: NSTableView) -> Int {
        entries.count
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        let entry = entries[row]
        let cell = NSTableCellView()
        let text = NSTextField(labelWithString: "\(entry.pinned ? "[P] " : "")\(entry.contentType.uppercased())  \(entry.preview)")
        text.lineBreakMode = .byTruncatingTail
        text.maximumNumberOfLines = 2
        text.translatesAutoresizingMaskIntoConstraints = false
        cell.addSubview(text)
        NSLayoutConstraint.activate([
            text.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 8),
            text.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -8),
            text.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
        ])
        return cell
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        updatePreview()
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
        let row = tableView.selectedRow
        guard row >= 0, row < entries.count else { return nil }
        return entries[row]
    }

    private func buildUI(in window: NSWindow) {
        let root = NSStackView()
        root.orientation = .vertical
        root.spacing = 8
        root.edgeInsets = NSEdgeInsets(top: 10, left: 10, bottom: 10, right: 10)
        root.translatesAutoresizingMaskIntoConstraints = false
        let contentView = NSView()
        window.contentView = contentView
        contentView.addSubview(root)

        let toolbar = NSStackView()
        toolbar.orientation = .horizontal
        toolbar.spacing = 8
        searchField.placeholderString = "Search"
        searchField.delegate = self
        searchField.translatesAutoresizingMaskIntoConstraints = false
        searchField.widthAnchor.constraint(greaterThanOrEqualToConstant: 260).isActive = true

        let copyButton = NSButton(title: "Copy", target: self, action: #selector(copySelectedToPasteboard(_:)))
        let deleteButton = NSButton(title: "Delete", target: self, action: #selector(deleteSelected(_:)))
        pinButton.target = self
        pinButton.action = #selector(togglePin(_:))

        toolbar.addArrangedSubview(searchField)
        toolbar.addArrangedSubview(copyButton)
        toolbar.addArrangedSubview(deleteButton)
        toolbar.addArrangedSubview(pinButton)
        root.addArrangedSubview(toolbar)

        let splitView = NSSplitView()
        splitView.isVertical = true
        splitView.dividerStyle = .thin
        splitView.translatesAutoresizingMaskIntoConstraints = false
        root.addArrangedSubview(splitView)
        splitView.heightAnchor.constraint(greaterThanOrEqualToConstant: 420).isActive = true

        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("history"))
        column.title = "History"
        tableView.addTableColumn(column)
        tableView.headerView = nil
        tableView.delegate = self
        tableView.dataSource = self
        tableView.rowHeight = 38
        tableView.target = self
        tableView.doubleAction = #selector(copySelectedToPasteboard(_:))

        let listScroll = NSScrollView()
        listScroll.documentView = tableView
        listScroll.hasVerticalScroller = true
        listScroll.translatesAutoresizingMaskIntoConstraints = false
        listScroll.widthAnchor.constraint(equalToConstant: 330).isActive = true
        splitView.addArrangedSubview(listScroll)

        let detail = NSStackView()
        detail.orientation = .vertical
        detail.spacing = 6
        detail.edgeInsets = NSEdgeInsets(top: 0, left: 8, bottom: 0, right: 0)
        splitView.addArrangedSubview(detail)

        typeLabel.font = .boldSystemFont(ofSize: 14)
        metadataLabel.textColor = .secondaryLabelColor
        detail.addArrangedSubview(typeLabel)
        detail.addArrangedSubview(metadataLabel)

        textView.isEditable = false
        textView.isRichText = false
        textView.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        let textScroll = NSScrollView()
        textScroll.documentView = textView
        textScroll.hasVerticalScroller = true
        detail.addArrangedSubview(textScroll)

        imageView.imageScaling = .scaleProportionallyUpOrDown
        imageView.isHidden = true
        detail.addArrangedSubview(imageView)

        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor),
            root.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor),
            root.topAnchor.constraint(equalTo: window.contentView!.topAnchor),
            root.bottomAnchor.constraint(equalTo: window.contentView!.bottomAnchor),
            textScroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 320),
            imageView.heightAnchor.constraint(greaterThanOrEqualToConstant: 320)
        ])
    }

    private func updatePreview() {
        guard let entry = selectedEntry else {
            typeLabel.stringValue = "No item selected"
            metadataLabel.stringValue = ""
            textView.string = ""
            imageView.image = nil
            imageView.isHidden = true
            textView.enclosingScrollView?.isHidden = false
            pinButton.title = "Pin"
            return
        }

        typeLabel.stringValue = "\(entry.contentType.uppercased())  \(entry.pinned ? "Pinned" : "")"
        metadataLabel.stringValue = "\(entry.byteSize) bytes  •  \(displayDate(entry.createdAt))  •  \(entry.source)"
        pinButton.title = entry.pinned ? "Unpin" : "Pin"

        if entry.contentType == "image", let data = imageData(from: entry.content), let image = NSImage(data: data) {
            imageView.image = image
            imageView.isHidden = false
            textView.enclosingScrollView?.isHidden = true
        } else {
            imageView.isHidden = true
            textView.enclosingScrollView?.isHidden = false
            textView.string = previewText(for: entry)
        }
    }

    private func moveSelection(delta: Int) {
        guard !entries.isEmpty else { return }
        let current = tableView.selectedRow < 0 ? 0 : tableView.selectedRow
        let next = max(0, min(entries.count - 1, current + delta))
        tableView.selectRowIndexes(IndexSet(integer: next), byExtendingSelection: false)
        tableView.scrollRowToVisible(next)
    }

    private func write(entry: ClipboardEntry, to pasteboard: NSPasteboard) throws {
        let content = try parseContent(entry.content)
        pasteboard.clearContents()

        switch content {
        case .text(let text):
            pasteboard.declareTypes([.string, selfWriteType], owner: nil)
            pasteboard.setString(text, forType: .string)
            pasteboard.setString("1", forType: selfWriteType)
        case .url(let url):
            pasteboard.declareTypes([.URL, .string, selfWriteType], owner: nil)
            pasteboard.setString(url, forType: .URL)
            pasteboard.setString(url, forType: .string)
            pasteboard.setString("1", forType: selfWriteType)
        case .files(let paths):
            let urls = paths.map { NSURL(fileURLWithPath: $0) }
            pasteboard.writeObjects(urls)
            pasteboard.setString("1", forType: selfWriteType)
        case .image(let image):
            guard let raw = image.rawData, let data = Data(base64Encoded: raw) else {
                throw CopyError.unsupported
            }
            pasteboard.declareTypes([.png, selfWriteType], owner: nil)
            pasteboard.setData(data, forType: .png)
            pasteboard.setString("1", forType: selfWriteType)
        }
    }

    private func previewText(for entry: ClipboardEntry) -> String {
        guard let content = try? parseContent(entry.content) else { return entry.content }
        switch content {
        case .text(let text): return text
        case .url(let url): return url
        case .files(let paths): return paths.joined(separator: "\n")
        case .image: return entry.preview
        }
    }

    private func parseContent(_ content: String) throws -> RustClipboardContent {
        guard let data = content.data(using: .utf8) else {
            throw CopyError.unsupported
        }
        return try jsonDecoder.decode(RustClipboardContent.self, from: data)
    }

    private func imageData(from content: String) -> Data? {
        guard let parsed = try? parseContent(content),
              case .image(let image) = parsed,
              let raw = image.rawData else { return nil }
        return Data(base64Encoded: raw)
    }

    private func displayDate(_ value: String) -> String {
        if let date = ISO8601DateFormatter.oclip.date(from: value) {
            return DateFormatter.oclip.string(from: date)
        }
        return value
    }
}

enum CopyError: LocalizedError {
    case unsupported

    var errorDescription: String? { "Unsupported clipboard content" }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private var store: ClipboardStore?
    private var monitor: ClipboardMonitor?
    private var windowController: ClipboardWindowController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        installMainMenu()

        do {
            let config = AppConfig.load()
            let store = try ClipboardStore(path: config.databaseURL)
            self.store = store
            let controller = ClipboardWindowController(store: store)
            self.windowController = controller
            let monitor = ClipboardMonitor(store: store, config: config)
            monitor.onChange = { [weak controller] in controller?.reload() }
            monitor.start()
            self.monitor = monitor
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

    @objc private func quit(_ sender: Any?) {
        NSApp.terminate(nil)
    }

    private func installStatusItem() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.title = "O-Clip"
        item.button?.target = self
        item.button?.action = #selector(toggleWindow(_:))
        item.button?.sendAction(on: [.leftMouseUp, .rightMouseUp])
        statusItem = item
    }

    private func showStatusMenu() {
        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "Open O-Clip", action: #selector(showWindow(_:)), keyEquivalent: ""))
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
        withUnsafeBytes(of: &little) { append(contentsOf: $0) }
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

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
