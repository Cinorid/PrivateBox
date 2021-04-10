using NUnit.Framework;
using Sodium;
using System;
using System.Collections.Generic;
using System.Text;

namespace AuditDrivenCrypto.Tests
{
	public class Test_Benchmark
	{
		int N = 10000;
		byte[] content = PrivateBox.RandomBytes(1024);
		KeyPair alice = PublicKeyBox.GenerateKeyPair();
		KeyPair bob = PublicKeyBox.GenerateKeyPair();

		public byte[] Create(int n, int max, byte[] pk)
		{
			var a = new byte[n][];
			a[0] = pk;
			for (int i = 1; i < n; i++)
			{
				a[i] = PublicKeyBox.GenerateKeyPair().PublicKey;
			}

			return PrivateBox.Encrypt(content, a, max);
		}

		public void Bench(int max, int N)
		{
			var ctxt = Create(max , max, alice.PublicKey);
			System.Diagnostics.Trace.WriteLine("max: " + max); //number of recipients
															   //length of cyphertext, ratio of cyphertext to plaintext length
			System.Diagnostics.Trace.WriteLine("length " + ctxt.Length + " " + ctxt.Length / content.Length);
			var start = DateTime.Now;
			for (var i = 0; i < N; i++)
			{
				PrivateBox.Decrypt(ctxt, alice.PrivateKey, max);
			}
			var hit = DateTime.Now - start;
			System.Diagnostics.Trace.WriteLine("hit " + hit / N); //ms to decrypt a message that was for us

			start = DateTime.Now;
			for (var i = 0; i < N; i++)
			{
				PrivateBox.Decrypt(ctxt, bob.PrivateKey, max);
			}
			var miss = DateTime.Now - start;
			System.Diagnostics.Trace.WriteLine("miss " + miss / N); //ms to fail to decrypt a message not for us

			System.Diagnostics.Trace.WriteLine("ratio " + miss / hit); //how much miss is bigger than hit.
		}

		[Test]
		public void Bench4()
		{
			Bench(4, N);
		}

		//[Test]
		public void Bench8()
		{
			Bench(8, N);
		}

		//[Test]
		public void Bench16()
		{
			Bench(16, N);
		}

		//[Test]
		public void Bench32()
		{
			Bench(32, N);
		}

		//[Test]
		public void Bench64()
		{
			Bench(64, N);
		}

		//[Test]
		public void Bench128()
		{
			Bench(128, N);
		}
	}
}
