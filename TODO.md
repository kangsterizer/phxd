# phxd TODO

Tracking deferred work for the Python 3 port and beyond.

## Banner support (`tranDownloadBanner`, 0xD4)

**Status:** Stubbed. `handleDownloadBanner` in `server/handlers/UserHandler.py` currently replies with an empty `HTLS_HDR_TASK` ack, which clients interpret as "no banner."

**Why this matters:** Hotline 1.5+ clients (including the classic 1.5 / 1.8 / 1.9 builds and the Mierau Swift client) send `tranDownloadBanner` immediately after login and display the returned image in their UI. Today every connecting client sees a blank banner area.

**Acceptance criteria:**

- A configurable banner image path in `config.py` (e.g. `BANNER_PATH = "support/banner.jpg"`), with a sensible default that points at a checked-in placeholder.
- Support at least JPEG; GIF is a nice-to-have. Size is conventionally 468×60 px — document this in the config comment.
- `handleDownloadBanner` should:
  - If the configured banner file is missing or unreadable, fall back to the current empty-ack behavior (no error to the client, log a warning once on startup).
  - If the banner file exists, reply with `DATA_BANNERTYPE` set to the appropriate type constant and either inline the bytes via `DATA_BANNERIMAGE` or set up a file-transfer handle (mirror `handleFileDownload`'s pattern: register with `server.fileserver.addDownload`, return `DATA_XFERID` / `DATA_XFERSIZE` / `DATA_FILESIZE` as 32-bit ints).
- Verify against both the Mierau Swift client and a classic 1.8/1.9 client under WINE — both should display the banner.
- Banner bytes should be cached in memory on first read (and on a config reload signal if we ever add one) rather than re-read from disk on every connect.

**References:**

- Hotline protocol docs (Higher Intellect Vintage Wiki, Hotline Wiki Fandom) for the exact `DATA_BANNER*` field IDs and bannertype constants.
- Existing `handleFileDownload` in `server/handlers/FileHandler.py` is the closest existing pattern for the file-transfer path.
- The protocol constant `HTLC_HDR_DOWNLOAD_BANNER = 0x000000D4` is already defined in `shared/HLProtocol.py`.

**Out of scope for this item:** Per-account or per-server-state dynamic banners (e.g. rotating, time-based, or admin-uploadable). Add as a follow-up if desired.

## Threaded news (Hotline 1.5+)

**Status:** Stubbed. `NewsHandler.handleThreadedStub` returns an empty `HTLS_HDR_TASK` ack for `tranGetNewsCatNameList` (0x172), `tranGetNewsArtNameList` (0x173), and `tranGetNewsArtData` (0x190). The client renders an empty news pane and doesn't error.

**Why this matters:** The classic 1.5+ client (and modern clients) have a separate "threaded news" pane built around categories, folders, articles, and reply threading — distinct from the old flat news (`HTLC_HDR_NEWS_GET` at 0x65) we already implement. Right now an admin opening that pane sees nothing.

**Acceptance criteria:**

- A storage layer for threaded news. Simplest first cut: a directory tree under `DB_FILE_BASEPATH/threaded_news/` where each subdirectory is a category, each `.art` file is an article, and a small index file in each category tracks article ordering and parent-thread links.
- Wire transactions to implement (constants already declared in `shared/HLProtocol.py`):
  - `tranGetNewsCatNameList` (0x172) — list categories at a path. Reply with one `DATA_NEWS_CAT_NAME` field per category, each containing the category name plus type (category vs. folder) and article count.
  - `tranGetNewsArtNameList` (0x173) — list articles in a category. Reply with article ID, parent ID, title, poster nick/login, post date, flags.
  - `tranGetNewsArtData` (0x190) — retrieve an article body by ID. Reply with title, poster info, date, MIME type, body.
  - `tranNewNewsCat` (0x174) — create a category. Gated by an admin priv bit (Hotline historically used `PRIV_NEWS_CREATE_CATEGORY` etc. — declare new priv constants).
  - `tranNewNewsFldr` (0x175) — create a folder/bundle within a category.
  - `tranDelNewsItem` (0x178) — delete a category or folder.
  - `tranPostNewsArt` (0x19A) — post a new article (or reply to one via a parent ID).
  - `tranDelNewsArt` (0x19B) — delete an article.
- Privilege gating: read access tied to `PRIV_READ_NEWS` (existing); post access tied to `PRIV_POST_NEWS` (existing); create-category and delete-category should use new priv bits with sane defaults so guests can't reshape the news tree.
- Article IDs need to be stable and unique within a category (a monotonic counter persisted alongside the index file works).
- Verify against both the classic 1.9 client and the Mierau Swift client — both should be able to browse, post, and reply.
- The existing flat news (`HTLC_HDR_NEWS_GET`) should remain untouched and keep working in parallel.

**References:**

- Hotline protocol docs (Higher Intellect Vintage Wiki, Hotline Wiki Fandom) for the exact `DATA_NEWS_*` field IDs and reply structures.
- The flat-news `handleNewsGet` / `handleNewsPost` in `server/handlers/NewsHandler.py` is the closest internal reference for HL packet construction patterns.

**Out of scope for this item:** Cross-server news federation; rich text / HTML article bodies (text/plain is fine for first cut); article search.
