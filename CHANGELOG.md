# Changelog

## [0.23.0] 2025-08-13
### Fixed
- Timestamps are Nullable. Null timestamps use the `-` NULLVALUE character.

## [0.22.0] 2025-06-16
### Fixed
- `:` at the end of msgid can now be parsed successfully, F5 logs can be parsed now.
- 3164 messages with invalid structured data segments will parse successfully. The structured data segment is considered part of the message.
