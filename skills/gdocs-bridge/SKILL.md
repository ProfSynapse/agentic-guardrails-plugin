---
name: gdocs-bridge
description: >
  Handling Google Docs/Sheets/Slides files that appear in a Google Drive for
  desktop synced folder as .gdoc/.gsheet/.gslides files. Use when a task
  involves one of these extensions or when the user asks to edit a Google Doc
  from their local Drive folder.
---

# Google Docs Bridge

`.gdoc`, `.gsheet`, `.gslides` (and `.gdraw`, `.gform`, `.gmap`, `.gsite`)
files in a Drive synced folder are **not documents**. Each is a tiny JSON stub
containing a URL and document ID. The real content lives only in Google's
editors.

## Hard rules

- **Never edit a stub.** Writing markdown or document content into a `.gdoc`
  corrupts the pointer; the hook denies this. Don't rename their extension
  either.
- You can **read** a stub to extract its `url` / `doc_id` — that's the bridge.

## How to actually work with the content

1. Read the stub to get the document URL/ID.
2. Get real content via whichever channel is available, in order of preference:
   - A connected Google Drive MCP/connector: export the doc (Docs export to
     markdown natively; Sheets to csv/xlsx).
   - Ask the user to download it (File → Download → Markdown/docx/csv) into
     the working folder, then use the normal `agw checkout` flow on that file.
3. Edit the exported open-format file in `_workspace/` as usual.
4. Publishing back:
   - Via connector: update the document content through the API (updates
     preserve the file ID, so sharing links keep working). Create-new-file
     only if the user agrees — it gets a new ID.
   - No connector: hand the finished file back to the user to upload/import,
     and say clearly that the Google Doc itself was not modified.

## Things that look like they'd work but don't

- Replacing `Report.gdoc` with `Report.docx` in the synced folder does **not**
  update the Google Doc — it creates a second, unrelated file in Drive.
- Deleting a stub deletes the real cloud document for everyone. Deletion is
  blocked anyway; never archive a stub as a workaround without telling the user
  what that means.
