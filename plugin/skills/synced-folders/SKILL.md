---
name: synced-folders
description: >
  Safety rules for working inside cloud-synced folders — OneDrive, SharePoint
  synced libraries, Google Drive for desktop, Dropbox. Use whenever a task
  touches files under a synced folder, before bulk operations, or when a file
  read returns empty/garbage content for a file that clearly should have data.
---

# Cloud-Synced Folders

Synced folders look like normal directories but have three hazards: cloud-only
placeholders, pointer stubs, and sync-conflict artifacts. The hooks catch most
of this, but knowing why keeps you out of the ask-loop.

## Before bulk work: scan

```
agw scan <folder> --json
```

Reports per folder: total files, **placeholders** (cloud-only, not hydrated),
**gdoc_stubs** (.gdoc/.gsheet/.gslides pointer files), and **sync artifacts**
(conflict copies, .tmp.driveupload, ~$ lock files). Plan around these before
touching anything.

## Placeholders (cloud-only files)

OneDrive Files On-Demand and Drive "online-only" files occupy zero local
blocks; the bytes live in the cloud. Reading one through normal tools can
return empty content, and **writing one can permanently destroy the cloud
copy** (this is a real, documented data-loss class).

- The hook denies writes to placeholders and asks before reads.
- If the user needs the file, ask them to make it "Always keep on this device"
  (OneDrive) or "Available offline" (Drive/Dropbox), then re-scan.

## Sync artifacts — leave them alone

- `ConflictedCopy` / `conflicted copy` files (Dropbox), `-PC-name` copies
  (OneDrive): these hold a human's unmerged work. Never archive or overwrite
  them without explicit instruction.
- `~$xxxx.docx` Office lock files and `.tmp.driveupload`: transient; ignore.

## Working etiquette in synced trees

- Prefer the checkout/publish flow (see the agent-workspace skill); publish
  replaces files atomically, which sync clients handle cleanly.
- Avoid long-running partial writes to synced files — the client may upload a
  half-written file. Write elsewhere, then `agw publish` or `agw move`.
- The archive store is deliberately **outside** synced trees (`~/.agw`) so
  versions don't churn sync quota. Don't relocate it into a synced folder.
