// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

using Torann.Crypto;
using Xunit;

namespace Torann.Tests;

/// <summary>
/// The Diffie-Hellman examples of RFC 7748 §6.1 (X25519) and §6.2 (X448): Alice's and
/// Bob's private keys derive the published public keys, and both orders of the DH
/// function give the published shared secret. The DH function is reached through the
/// internal <see cref="NoiseProtocol.Dh"/> property.
/// </summary>
public class Rfc7748Tests
{
    [Theory]
    [InlineData(
        "Noise_NN_25519_ChaChaPoly_SHA256",
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")]
    [InlineData(
        "Noise_NN_448_ChaChaPoly_SHA256",
        "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
        "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
        "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
        "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
        "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d")]
    public void KeyDerivationAndSharedSecretMatchRfc7748(
        string protocolName, string alicePrivate, string alicePublic, string bobPrivate, string bobPublic, string shared)
    {
        var protocol = NoiseProtocol.Parse(protocolName);
        using var alice = protocol.CreateKeyPair(Convert.FromHexString(alicePrivate));
        using var bob = protocol.CreateKeyPair(Convert.FromHexString(bobPrivate));
        Assert.Equal(alicePublic, Convert.ToHexStringLower(alice.PublicKey));
        Assert.Equal(bobPublic, Convert.ToHexStringLower(bob.PublicKey));

        IDhFunction dh = protocol.Dh;
        var fromAlice = new byte[dh.DhLen];
        var fromBob = new byte[dh.DhLen];
        dh.Dh(alice.PrivateKey, bob.PublicKey, fromAlice);
        dh.Dh(bob.PrivateKey, alice.PublicKey, fromBob);
        Assert.Equal(shared, Convert.ToHexStringLower(fromAlice));
        Assert.Equal(shared, Convert.ToHexStringLower(fromBob));
    }
}
