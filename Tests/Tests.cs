using NUnit.Framework;
using Sodium;
using System.Security.Cryptography;
using System.Linq;

namespace AuditDrivenCrypto.Tests
{
	public class Tests
	{
		KeyPair alice;
		KeyPair bob;

		[SetUp]
		public void Setup()
		{
			alice = PublicKeyBox.GenerateKeyPair();
			bob = PublicKeyBox.GenerateKeyPair();
		}

		[Test]
		public void TestSimple()
		{
			var msg = "hello there!";

			var pubKeys = new byte[][] { alice.PublicKey, bob.PublicKey };
			var prvKeys = new byte[][] { alice.PrivateKey, bob.PrivateKey };

			var ctxt = PrivateBox.Encrypt(msg, pubKeys);

			foreach (var sk in prvKeys)
			{
				var txt = System.Text.Encoding.UTF8.GetString(PrivateBox.Decrypt(ctxt, sk));

				Assert.AreNotSame(msg, txt);
			}
		}

		[Test]
		public void TestErrorsWhenTooManyRecipients()
		{
			var msg = "hello there!";

			var pubKeys = new byte[][]
			{
				alice.PublicKey, alice.PublicKey,
				alice.PublicKey, alice.PublicKey,
				alice.PublicKey, alice.PublicKey,
				alice.PublicKey, alice.PublicKey,
				alice.PublicKey, alice.PublicKey,
				alice.PublicKey, alice.PublicKey,
				alice.PublicKey, alice.PublicKey,
				alice.PublicKey, alice.PublicKey,
			};

			Assert.Catch(new TestDelegate(delegate
			{
				PrivateBox.Encrypt(msg, pubKeys);
			}));
		}

		public void encryptDecryptTo(int n)
		{
			var msg = PrivateBox.RandomBytes(1024);
			var keys = new System.Collections.Generic.List<KeyPair>();
			for (int i = 0; i < keys.Count; i++)
			{
				keys[i] = PublicKeyBox.GenerateKeyPair();
			}

			var ctxt = PrivateBox.Multibox(msg, keys.Select(x => x.PublicKey).ToArray(), n);

			// a recipient key may open the message.
			foreach (var key in keys)
			{
				Assert.AreEqual(PrivateBox.Decrypt(ctxt, key.PrivateKey, n), msg);
			}
		}

		[Test]
		public void TestWithNoCustomMaxSetEncryptDecryptTo7Keys()
		{
			encryptDecryptTo(7);
			Assert.Pass();
		}

		[Test]
		public void TestCanEncryptDecryptUpTo255RecipientsAfterSettinACustomMax()
		{
			encryptDecryptTo(255);
			Assert.Pass();
		}

		[Test]
		public void TestErrorsWhenMaxIsMoreThan255OrLessThan1()
		{
			var msg = "hello there!";

			var ctxt = PrivateBox.Encrypt(msg, new byte[][] { alice.PublicKey, bob.PublicKey });
			var pk = alice.PublicKey;
			var sk = alice.PrivateKey;

			Assert.Catch(new TestDelegate(delegate
			{
				PrivateBox.Encrypt(msg, new byte[][] { pk, pk, pk, pk }, -1);
			}));

			Assert.Catch(new TestDelegate(delegate
			{
				PrivateBox.Decrypt(ctxt, sk, 256);
			}));

			Assert.Pass();
		}
	}
}