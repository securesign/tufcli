// Stub implementations of PC/SC symbols for link-time satisfaction.
// At runtime, the real libpcsclite.so.1 must be present on the host.
// SPDX-License-Identifier: BSD-3-Clause

long SCardEstablishContext() { return 0; }
long SCardReleaseContext() { return 0; }
long SCardConnect() { return 0; }
long SCardDisconnect() { return 0; }
long SCardBeginTransaction() { return 0; }
long SCardEndTransaction() { return 0; }
long SCardTransmit() { return 0; }
long SCardListReaders() { return 0; }

struct { unsigned long dwProtocol; unsigned long cbPciLength; } g_rgSCardT1Pci = {0, 0};
