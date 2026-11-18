# Editing project documentation

Follow the [contribution guide](../CONTRIBUTING.md). Preserve the reader,
purpose, terminology and useful structure of existing text. Make the smallest
edit that corrects the issue. A change elsewhere in the repository does not
authorize rewriting a guide.

Use the current behavior and tests as evidence. For network changes, compare
the [request policy](../crates/protocol/src/request_policy.rs), control handler
and [connectivity contract](change-safety.md). Keep quick-start instructions
task-oriented and link to the reference for implementation details.

Keep published recovery heading IDs and API example markers stable when
editing the surrounding text. If an accepted editorial decision conflicts with
a new requirement, explain the conflict for maintainer review before replacing
the relevant text.
