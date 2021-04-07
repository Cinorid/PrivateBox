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

			var ctxt = PrivateBox.Multibox(msg, new byte[][] { alice.PublicKey, bob.PublicKey }, 2);

			var pvKeys = new byte[][] { alice.PrivateKey, bob.PrivateKey };
			foreach (var sk in pvKeys)
			{
				var txt = System.Text.Encoding.UTF8.GetString(PrivateBox.MultiboxOpen(ctxt, sk, 2));

				Assert.AreNotSame(msg, txt);
			}
		}
	}
}