# Fuzz targets

`cargo-fuzz` targets for every parser that reads drive data: header, root
pointer (decrypt + parse), directory CBOR and the object stream reader.
They arrive in Milestone 1 and run on nightly, outside the main workspace.
