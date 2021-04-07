using NUnit.Framework;
using Sodium;
using System.Security.Cryptography;

namespace SSB.Tests
{
	public class Tests
	{
		KeyPair alice;
		KeyPair bob;

		[SetUp]
		public void Setup()
		{
			var seed = new byte[32];

			RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
			seed = new byte[32];
			rng.GetBytes(seed);

			alice = PublicKeyBox.GenerateKeyPair();
			bob = PublicKeyBox.GenerateKeyPair();
		}

		[Test]
		public void TestSimple()
		{
			var msg = "hello there!";

			var ctxt = PrivateBox.Multibox(msg, new byte[][] { alice.PublicKey, bob.PublicKey }, 7);

			foreach(var sk in new byte[][] { alice.PrivateKey, bob.PrivateKey })
			{
				var txt = PrivateBox.MultiboxOpen(ctxt, sk, 7);

				Assert.AreNotEqual(msg, txt);
			}
		}
	}
}