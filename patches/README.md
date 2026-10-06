# Engine patch provenance

`sleuthkit/exfat-utc-offset.patch` is the reviewed exFAT timestamp patch selected for the Phase 1 Sleuth Kit 4.15.0 backend. It honors valid per-entry signed 15-minute UTC offsets and retains the upstream timezone fallback when an offset is unknown.

SHA-256: `fe17dab7a4f83f774eb9b4992801033131e66bf9579e91bc0e5aa5a5309613cf`

Base source: [Sleuth Kit](https://github.com/sleuthkit/sleuthkit), `tsk/fs/exfatfs_meta.c`, version 4.15.0. Upstream licensing remains applicable to the upstream source/context; see its [license inventory](https://github.com/sleuthkit/sleuthkit/blob/develop/licenses/README.md) and this project's third-party notices. No upstream runtime binaries are committed.

This patch is recorded for a reproducible future native engine build. **Phase 0 does not build or load Sleuth Kit.** Before integrating it, run the Phase 1 timezone and payload regressions in the roadmap, including multiple timezones, negative offsets, unknown offsets, subsecond values and date boundaries.
