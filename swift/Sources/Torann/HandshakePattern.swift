// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

enum Token: Sendable {
    case e, s, ee, es, se, ss, psk
}

/// A Noise handshake pattern: pre-message tokens for each party plus the sequence
/// of message patterns (Noise §7).
struct HandshakePattern: Sendable {
    let name: String
    let preInitiator: [Token]
    let preResponder: [Token]
    let messages: [[Token]]

    // One-way patterns (Noise §7.4).
    static let N = HandshakePattern(name: "N", preInitiator: [], preResponder: [.s], messages: [[.e, .es]])
    static let K = HandshakePattern(name: "K", preInitiator: [.s], preResponder: [.s], messages: [[.e, .es, .ss]])
    static let X = HandshakePattern(name: "X", preInitiator: [], preResponder: [.s], messages: [[.e, .es, .s, .ss]])

    // Fundamental interactive patterns (Noise §7.5).
    static let NN = HandshakePattern(name: "NN", preInitiator: [], preResponder: [], messages: [[.e], [.e, .ee]])
    static let NK = HandshakePattern(name: "NK", preInitiator: [], preResponder: [.s], messages: [[.e, .es], [.e, .ee]])
    static let NX = HandshakePattern(name: "NX", preInitiator: [], preResponder: [], messages: [[.e], [.e, .ee, .s, .es]])
    static let KN = HandshakePattern(name: "KN", preInitiator: [.s], preResponder: [], messages: [[.e], [.e, .ee, .se]])
    static let KK = HandshakePattern(name: "KK", preInitiator: [.s], preResponder: [.s], messages: [[.e, .es, .ss], [.e, .ee, .se]])
    static let KX = HandshakePattern(name: "KX", preInitiator: [.s], preResponder: [], messages: [[.e], [.e, .ee, .se, .s, .es]])
    static let XN = HandshakePattern(name: "XN", preInitiator: [], preResponder: [], messages: [[.e], [.e, .ee], [.s, .se]])
    static let XK = HandshakePattern(name: "XK", preInitiator: [], preResponder: [.s], messages: [[.e, .es], [.e, .ee], [.s, .se]])
    static let XX = HandshakePattern(name: "XX", preInitiator: [], preResponder: [], messages: [[.e], [.e, .ee, .s, .es], [.s, .se]])
    static let IN = HandshakePattern(name: "IN", preInitiator: [], preResponder: [], messages: [[.e, .s], [.e, .ee, .se]])
    static let IK = HandshakePattern(name: "IK", preInitiator: [], preResponder: [.s], messages: [[.e, .es, .s, .ss], [.e, .ee, .se]])
    static let IX = HandshakePattern(name: "IX", preInitiator: [], preResponder: [], messages: [[.e, .s], [.e, .ee, .se, .s, .es]])

    // Deferred patterns (Noise §7.6).
    static let NK1 = HandshakePattern(name: "NK1", preInitiator: [], preResponder: [.s], messages: [[.e], [.e, .ee, .es]])
    static let NX1 = HandshakePattern(name: "NX1", preInitiator: [], preResponder: [], messages: [[.e], [.e, .ee, .s], [.es]])
    static let X1N = HandshakePattern(name: "X1N", preInitiator: [], preResponder: [], messages: [[.e], [.e, .ee], [.s], [.se]])
    static let X1K = HandshakePattern(name: "X1K", preInitiator: [], preResponder: [.s], messages: [[.e, .es], [.e, .ee], [.s], [.se]])
    static let XK1 = HandshakePattern(name: "XK1", preInitiator: [], preResponder: [.s], messages: [[.e], [.e, .ee, .es], [.s, .se]])
    static let X1K1 = HandshakePattern(name: "X1K1", preInitiator: [], preResponder: [.s], messages: [[.e], [.e, .ee, .es], [.s], [.se]])
    static let X1X = HandshakePattern(name: "X1X", preInitiator: [], preResponder: [], messages: [[.e], [.e, .ee, .s, .es], [.s], [.se]])
    static let XX1 = HandshakePattern(name: "XX1", preInitiator: [], preResponder: [], messages: [[.e], [.e, .ee, .s], [.es, .s, .se]])
    static let X1X1 = HandshakePattern(name: "X1X1", preInitiator: [], preResponder: [], messages: [[.e], [.e, .ee, .s], [.es, .s], [.se]])
    static let K1N = HandshakePattern(name: "K1N", preInitiator: [.s], preResponder: [], messages: [[.e], [.e, .ee], [.se]])
    static let K1K = HandshakePattern(name: "K1K", preInitiator: [.s], preResponder: [.s], messages: [[.e, .es], [.e, .ee], [.se]])
    static let KK1 = HandshakePattern(name: "KK1", preInitiator: [.s], preResponder: [.s], messages: [[.e], [.e, .ee, .se, .es]])
    static let K1K1 = HandshakePattern(name: "K1K1", preInitiator: [.s], preResponder: [.s], messages: [[.e], [.e, .ee, .es], [.se]])
    static let K1X = HandshakePattern(name: "K1X", preInitiator: [.s], preResponder: [], messages: [[.e], [.e, .ee, .s, .es], [.se]])
    static let KX1 = HandshakePattern(name: "KX1", preInitiator: [.s], preResponder: [], messages: [[.e], [.e, .ee, .se, .s], [.es]])
    static let K1X1 = HandshakePattern(name: "K1X1", preInitiator: [.s], preResponder: [], messages: [[.e], [.e, .ee, .s], [.se, .es]])
    static let I1N = HandshakePattern(name: "I1N", preInitiator: [], preResponder: [], messages: [[.e, .s], [.e, .ee], [.se]])
    static let I1K = HandshakePattern(name: "I1K", preInitiator: [], preResponder: [.s], messages: [[.e, .es, .s], [.e, .ee], [.se]])
    static let IK1 = HandshakePattern(name: "IK1", preInitiator: [], preResponder: [.s], messages: [[.e, .s], [.e, .ee, .se, .es]])
    static let I1K1 = HandshakePattern(name: "I1K1", preInitiator: [], preResponder: [.s], messages: [[.e, .s], [.e, .ee, .es], [.se]])
    static let I1X = HandshakePattern(name: "I1X", preInitiator: [], preResponder: [], messages: [[.e, .s], [.e, .ee, .s, .es], [.se]])
    static let IX1 = HandshakePattern(name: "IX1", preInitiator: [], preResponder: [], messages: [[.e, .s], [.e, .ee, .se, .s], [.es]])
    static let I1X1 = HandshakePattern(name: "I1X1", preInitiator: [], preResponder: [], messages: [[.e, .s], [.e, .ee, .s], [.se, .es]])

    static let registry: [String: HandshakePattern] = Dictionary(uniqueKeysWithValues: [
        N, K, X,
        NN, NK, NX, KN, KK, KX, XN, XK, XX, IN, IK, IX,
        NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1,
        K1N, K1K, KK1, K1K1, K1X, KX1, K1X1,
        I1N, I1K, IK1, I1K1, I1X, IX1, I1X1,
    ].map { ($0.name, $0) })

    var hasInitiatorPreStatic: Bool { preInitiator.contains(.s) }
    var hasResponderPreStatic: Bool { preResponder.contains(.s) }

    var initiatorSendsStatic: Bool {
        hasInitiatorPreStatic || messages.enumerated().contains { $0.offset % 2 == 0 && $0.element.contains(.s) }
    }

    var responderSendsStatic: Bool {
        hasResponderPreStatic || messages.enumerated().contains { $0.offset % 2 == 1 && $0.element.contains(.s) }
    }

    func withPsks(_ positions: [Int]) throws -> HandshakePattern {
        if positions.isEmpty { return self }
        var messages = self.messages
        for position in positions {
            if position == 0 {
                messages[0].insert(.psk, at: 0)
            } else if position <= messages.count {
                messages[position - 1].append(.psk)
            } else {
                throw TorannError.unsupportedFunction("psk\(position) is out of range for pattern \(name).")
            }
        }
        return HandshakePattern(name: name, preInitiator: preInitiator, preResponder: preResponder, messages: messages)
    }
}
