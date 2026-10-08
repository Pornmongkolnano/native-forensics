# Reviewed PDF comparison contract

The comparison sheet accepts two distinct regular filesystem files from the same
evidence and recorded analysis. Complete UTF-8 inputs retain their 1 MiB input
limit and original schema 1 range/prompt behavior. PDF inputs use the existing
128 MiB document-decoder limit, sequential extraction and decoding. File extension
does not establish type: locally verified bytes and a fresh decoded PDF result
are required. A failed, encrypted, unsupported or unprovenanced decoder result
cannot be sent as a PDF disclosure.

PDF preparation uses the owned filesystem document-preview service. It freshly
checks extraction size/hash and the complete ordered source-container set before
and after decoding. The current schema 2 result carries the actual decoder
parser executable SHA-256, broker identity separately, contract identifier/version, isolation/CDHashes, fixed options
and their digest, and a digest over all returned raw text pages. Cached index text,
old previews and exported file paths cannot supply comparison evidence.

Selections and redactions are page-qualified, zero-based, half-open UTF-16 ranges
in the untouched text returned for that PDF page. The range input is
`page:start:end`, such as `2:0:120,3:10:50`. Page numbers are one-based. Ranges
cannot split a surrogate pair, cross a page boundary, overlap or use a missing
decoded page. Redaction subtracts raw-page ranges before building segments.
These coordinates describe derived text, never byte offsets in the original PDF.

PDF disclosure has a separate fixed cap of 16 KiB of UTF-8 text per PDF and
32 KiB of PDF text combined, at most 16 selected pages per PDF, 32 selected and
32 redacted intervals, and 64 surviving segments. UTF-8 files retain 32 KiB per
file. Every pair remains under the original 64 KiB combined text and 192 KiB
exact serialized-request caps. UTF-16 coordinates do not count as byte budgets.
JSON escaping, question, decoder/page receipts and optional prior answer are
included in the serialized request check; escaping amplification refuses the
request instead of expanding any cap. Boundary oracles recompute actual selected
UTF-8 bytes for Thai, emoji, page transitions, redactions and oversized output.
These are correctness checks, not a claim of measured runtime memory performance.

The exact review displays surviving text, page/range locations, source PDF hash
and byte count, per-page raw text hashes/lengths/truncation, decoder provenance,
and decoded/disclosed/omitted derived-text byte counts. Unselected page text,
thumbnails, arbitrary metadata and host paths are absent from the outgoing
context. The page inventory and whole-derived-text digest do not imply complete
text extraction, OCR, visual layout equivalence or coverage of omitted pages.

Inline markers remain `[[segmentID:start:end]]` with UTF-8 offsets inside the
disclosed segment, preserving existing UTF-8 citation syntax. The app converts
valid segment offsets to raw-page UTF-16 positions for PDFs. Citation opening
freshly extracts and decodes the original selection again, requires the same
source/binding, decoder/version/options/whole-text provenance, page and segment
digest, and displays only the cited span. A changed decoder or derived text is
stale even if the PDF source hash is unchanged. This verifies a disclosed span;
it does not verify the AI interpretation.

PDF comparisons use context/record/template version 2. Existing UTF-8-only
schema 1 histories remain decodable and retain their original prompt reconstruction.
Full retention stores the exact reviewed prompt and disclosed segments; digest-only
removes prompt and segment text, retaining location/provenance/digest receipts and
the question/answer, which may quote evidence. Neither mode retains all decoded
pages or redacted text automatically. Immutable publication and bounded history
paging use the existing case transaction service.

A follow-up binds the exact previous request, source pair, coordinate type,
decoder provenance, page coverage, selections, redactions and segment digests.
Any disclosure change clears the prior answer. Newly verified timestamps do not
change otherwise identical disclosure identity. Each follow-up still requires its
own exact review and fresh PDF verification before Send.

Synthetic provider responses and local disclosure/citation tests establish the
implemented bounds and mappings. They do not establish live account readiness,
a submitted provider request, a returned live model answer, clean-machine XPC
behavior or physical-device memory performance.
