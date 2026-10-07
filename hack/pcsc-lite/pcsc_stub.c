// Stub implementations of PC/SC symbols for link-time satisfaction.
// SCardEstablishContext and SCardListReaders return SCARD_E_NO_SERVICE
// so PIV fails gracefully ("smart card service not running") instead of
// crashing on platforms where the real PCSC library is absent.
// SPDX-License-Identifier: BSD-3-Clause

#define PCSC_E_NO_SERVICE 0x8010001DL

long SCardEstablishContext() { return PCSC_E_NO_SERVICE; }
long SCardReleaseContext() { return 0; }
long SCardConnect() { return 0; }
long SCardDisconnect() { return 0; }
long SCardBeginTransaction() { return 0; }
long SCardEndTransaction() { return 0; }
long SCardTransmit() { return 0; }
long SCardListReaders() { return PCSC_E_NO_SERVICE; }

struct { unsigned long dwProtocol; unsigned long cbPciLength; } g_rgSCardT1Pci = {0, 0};
