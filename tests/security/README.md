# Security regression corpus

These files are inert data. A test may parse them, but must never pass fixture
values to a shell, package manager, URL client, archive extractor, or privilege
boundary. Each rejected input names the stable reason code expected from the
production implementation.

The corpus covers catalog and TUF attacks, argument/option injection, Unicode
ambiguity, archive traversal and bombs, unsafe URLs and redirects, terminal
escape injection, and unsafe state permissions. Add a fixture before fixing a
new security issue so the regression remains independently reproducible.
