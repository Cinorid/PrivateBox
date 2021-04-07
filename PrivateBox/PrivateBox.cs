using System;
using System.Collections.Generic;
using System.Text;
using Sodium;

namespace SSB
{
	public class PrivateBox
	{
		private static int DEFAULT_MAX = 7;

		public static byte[] RandomBytes(int n)
		{
			return Sodium.SodiumCore.GetRandomBytes(n);
		}

		public static int SetMax(int m)
		{
			m = (m > 0) ? m : DEFAULT_MAX;
			if (m < 1 || m > 255)
				throw new Exception("max recipients must be between 0 and 255.");
			return m;
		}

		public static byte[] Multibox(string msg, byte[][] recipients, int max=7)
		{
			max = SetMax(max);

			if (recipients.Length > max)
			{
				throw new Exception("max recipients is:" + max + " found:" + recipients.Length);
			}

			var nonce = RandomBytes(24);
			var key = RandomBytes(32);
			var onetime = PublicKeyBox.GenerateKeyPair();

			var length_and_key = new List<byte>(new byte[recipients.Length]);
			length_and_key.AddRange(key);

			var res = new List<byte>(nonce);
			res.AddRange(onetime.PublicKey);

			foreach (var rec in recipients)
			{
				res.AddRange(SecretBox.Create(length_and_key.ToArray(), nonce, ScalarMult.Mult(onetime.PrivateKey, rec)));
			}
			res.AddRange(SecretBox.Create(msg, nonce, key));
			
			return res.ToArray();
		}

		public static byte[] MultiboxOpenKey(byte[] ctxt, byte[] sk, int max = 7)
		{
			max = SetMax(max);

			var nonce = SubArray(ctxt, 0, 24);
			var onetime_pk = SubArray(ctxt, 24, 24 + 32);
			var my_key = ScalarMult.Mult(sk, onetime_pk);
			//var key = 24 + 32;
			//var length = 24 + 32;
			var start = 24 + 32;
			var size = 32 + 1 + 16;
			for (var i = 0; i <= max; i++)
			{
				var s = start + size * i;

				if (s + size > (ctxt.Length - 16)) return null;

				var length_and_key = SecretBox.Open(SubArray(ctxt,s, s + size), nonce, my_key);

				if (length_and_key != null)
				{
					return length_and_key;
				}
			}

			return null;
		}

		public static byte[] MultiboxOpenBody(byte[] ctxt, byte[] length_and_key)
		{
			if (length_and_key == null) return null;
			var key = SubArray(length_and_key, 1, length_and_key.Length - 1);
			var length = length_and_key[0];
			var start = 24 + 32;
			var size = 32 + 1 + 16;
			var nonce = SubArray(ctxt, 0, 24);
			return SecretBox.Open(SubArray(ctxt, start + length * size, ctxt.Length - (start + length * size)), nonce, key);
		}

		public static byte[] MultiboxOpen(byte[] ctxt, byte[] sk, int max)
		{
			var _key = MultiboxOpenKey(ctxt, sk, max);
			if (_key != null)
			{
				return MultiboxOpenBody(ctxt, _key);
			}
			else
				return null;
		}

		public static T[] SubArray<T>(T[] data, int index, int length)
		{
			T[] result = new T[length];
			Array.Copy(data, index, result, 0, length);
			return result;
		}
	}
}
