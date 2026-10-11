// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

import Foundation

/// Overwrites the array's storage with zeros. `memset_s` is not removed by the
/// optimizer, unlike a plain loop that writes to memory that is never read again.
@inline(never)
func wipe(_ bytes: inout [UInt8]) {
    bytes.withUnsafeMutableBufferPointer { buffer in
        guard let base = buffer.baseAddress, buffer.count > 0 else { return }
        _ = memset_s(base, buffer.count, 0, buffer.count)
    }
}

func wipe(_ bytes: inout [UInt8]?) {
    if bytes != nil {
        wipe(&bytes!)
        bytes = nil
    }
}
