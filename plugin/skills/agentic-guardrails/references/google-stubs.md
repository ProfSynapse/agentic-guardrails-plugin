# Google pointer stubs

Files ending in `.gdoc`, `.gsheet`, `.gslides`, and related Google extensions
are small pointers, not local document content. Writing document text into one
corrupts the pointer; deleting or archiving one can delete the shared cloud item.

Read only enough pointer metadata to obtain the document URL or ID. Prefer a
connected Google Drive/Docs/Sheets/Slides capability to read or update the native
item. Otherwise ask the user to export or download an open format and work on
that exported file.

Creating a neighboring DOCX/XLSX/PPTX does not update the original Google item.
If no connector can publish changes, return the finished export and state clearly
that the native Google document was not modified.

Manual transcription is a last resort for short visible documents. Label it as
transcription, verify its beginning/end and basic structure, and never publish it
over the native item as though it were a lossless export.
