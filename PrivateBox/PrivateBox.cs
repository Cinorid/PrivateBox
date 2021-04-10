using System;
using System.Collections.Generic;
using System.Text;
using Sodium;

namespace AuditDrivenCrypto
{
	/// <summary>
	/// an unaddressed box, with a private note-to-self so the sender can remember who it was for.
	/// </summary>
	public static class PrivateBox
	{
		private const int DEFAULT_MAX = 7;

		/// <summary>
		/// Generate random bytes array
		/// </summary>
		/// <param name="count">length of bytes array</param>
		/// <returns></returns>
		public static byte[] RandomBytes(int count)
		{
			return SodiumCore.GetRandomBytes(count);
		}

		/// <summary>
		/// Takes a 'plaintext' Buffer of the message you want to encrypt,<para />
		/// and an array of recipient public keys.<para />
		/// Returns a message that is encrypted to all recipients<para />
		/// and openable by them with 'PrivateBox.MultiboxOpen'.<para />
		/// The 'recipients' must be between 1 and 7 items long.
		/// </summary>
		/// <param name="msg"></param>
		/// <param name="recipients"></param>
		/// <param name="maxRecipients"></param>
		/// <returns></returns>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		public static byte[] Multibox(byte[] msg, byte[][] recipients, int maxRecipients = DEFAULT_MAX)
		{
			if (maxRecipients < 1 || maxRecipients > 255)
			{
				throw new ArgumentOutOfRangeException("max recipients must be between 1 and 255.");
			}

			if (recipients.Length > maxRecipients)
			{
				throw new ArgumentOutOfRangeException("max recipients is:" + maxRecipients + " found:" + recipients.Length);
			}

			var nonce = RandomBytes(24);
			var key = RandomBytes(32);
			var onetime = PublicKeyBox.GenerateKeyPair();

			var length_and_key = new List<byte>();
			length_and_key.Add((byte)recipients.Length);
			length_and_key.AddRange(key);

			var res = new List<byte>();
			res.AddRange(nonce);
			res.AddRange(onetime.PublicKey);

			foreach (var rec in recipients)
			{
				res.AddRange(SecretBox.Create(length_and_key.ToArray(), nonce, ScalarMult.Mult(onetime.PrivateKey, rec)));
			}
			res.AddRange(SecretBox.Create(msg, nonce, key));

			return res.ToArray();
		}

		/// <summary>
		/// Takes a 'plaintext' Buffer of the message you want to encrypt,<para />
		/// and an array of recipient public keys.<para />
		/// Returns a message that is encrypted to all recipients<para />
		/// and openable by them with 'PrivateBox.MultiboxOpen'.<para />
		/// The 'recipients' must be between 1 and 7 items long.
		/// </summary>
		/// <param name="msg"></param>
		/// <param name="recipients"></param>
		/// <param name="maxRecipients"></param>
		/// <returns></returns>
		public static byte[] Multibox(byte[] msg, List<byte[]> recipients, int maxRecipients = DEFAULT_MAX)
		{
			return Multibox(msg, recipients.ToArray(), maxRecipients);
		}

		/// <summary>
		/// Takes a 'plaintext' Buffer of the message you want to encrypt and encode it to UTF8 bytes array,<para />
		/// and an array of recipient public keys.<para />
		/// Returns a message that is encrypted to all recipients<para />
		/// and openable by them with 'PrivateBox.MultiboxOpen'.<para />
		/// The 'recipients' must be between 1 and 7 items long.
		/// </summary>
		/// <param name="msg"></param>
		/// <param name="recipients"></param>
		/// <param name="maxRecipients"></param>
		/// <returns></returns>
		public static byte[] Multibox(string msg, byte[][] recipients, int maxRecipients = DEFAULT_MAX)
		{
			var _msg = Encoding.UTF8.GetBytes(msg);
			return Multibox(_msg, recipients, maxRecipients);
		}

		/// <summary>
		/// Takes a 'plaintext' Buffer of the message you want to encrypt and encode it to UTF8 bytes array,<para />
		/// and an array of recipient public keys.<para />
		/// Returns a message that is encrypted to all recipients<para />
		/// and openable by them with 'PrivateBox.MultiboxOpen'.<para />
		/// The 'recipients' must be between 1 and 7 items long.
		/// </summary>
		/// <param name="msg"></param>
		/// <param name="recipients"></param>
		/// <param name="maxRecipients"></param>
		/// <returns></returns>
		public static byte[] Multibox(string msg, List<byte[]> recipients, int maxRecipients = DEFAULT_MAX)
		{
			var _msg = Encoding.UTF8.GetBytes(msg);
			return Multibox(_msg, recipients.ToArray(), maxRecipients);
		}

		/// <summary>
		/// Takes a 'plaintext' Buffer of the message you want to encrypt,<para />
		/// and an array of recipient public keys.<para />
		/// Returns a message that is encrypted to all recipients<para />
		/// and openable by them with 'PrivateBox.MultiboxOpen'.<para />
		/// The 'recipients' must be between 1 and 7 items long.
		/// same as Multibox
		/// </summary>
		/// <param name="msg"></param>
		/// <param name="recipients"></param>
		/// <param name="maxRecipients"></param>
		/// <returns></returns>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		public static byte[] Encrypt(byte[] msg, byte[][] recipients, int maxRecipients = DEFAULT_MAX)
		{
			return Multibox(msg, recipients, maxRecipients);
		}

		/// <summary>
		/// Takes a 'plaintext' Buffer of the message you want to encrypt,<para />
		/// and an array of recipient public keys.<para />
		/// Returns a message that is encrypted to all recipients<para />
		/// and openable by them with 'PrivateBox.MultiboxOpen'.<para />
		/// The 'recipients' must be between 1 and 7 items long.
		/// same as Multibox
		/// </summary>
		/// <param name="msg"></param>
		/// <param name="recipients"></param>
		/// <param name="maxRecipients"></param>
		/// <returns></returns>
		public static byte[] Encrypt(byte[] msg, List<byte[]> recipients, int maxRecipients = DEFAULT_MAX)
		{
			return Multibox(msg, recipients, maxRecipients);
		}

		/// <summary>
		/// Takes a 'plaintext' Buffer of the message you want to encrypt and encode it to UTF8 bytes array,<para />
		/// and an array of recipient public keys.<para />
		/// Returns a message that is encrypted to all recipients<para />
		/// and openable by them with 'PrivateBox.MultiboxOpen'.<para />
		/// The 'recipients' must be between 1 and 7 items long.
		/// same as Multibox
		/// </summary>
		/// <param name="msg"></param>
		/// <param name="recipients"></param>
		/// <param name="maxRecipients"></param>
		/// <returns></returns>
		public static byte[] Encrypt(string msg, byte[][] recipients, int maxRecipients = DEFAULT_MAX)
		{
			return Multibox(msg, recipients, maxRecipients);
		}

		/// <summary>
		/// Takes a 'plaintext' Buffer of the message you want to encrypt and encode it to UTF8 bytes array,<para />
		/// and an array of recipient public keys.<para />
		/// Returns a message that is encrypted to all recipients<para />
		/// and openable by them with 'PrivateBox.MultiboxOpen'.<para />
		/// The 'recipients' must be between 1 and 7 items long.
		/// same as Multibox
		/// </summary>
		/// <param name="msg"></param>
		/// <param name="recipients"></param>
		/// <param name="maxRecipients"></param>
		/// <returns></returns>
		public static byte[] Encrypt(string msg, List<byte[]> recipients, int maxRecipients = DEFAULT_MAX)
		{
			return Multibox(msg, recipients, maxRecipients);
		}

		/// <summary>
		/// MultiboxOpenKey
		/// </summary>
		/// <param name="cypherText"></param>
		/// <param name="secretKey"></param>
		/// <param name="maxRecipients"></param>
		/// <returns>return null if secretKey is not valid</returns>
		public static byte[] MultiboxOpenKey(byte[] cypherText, byte[] secretKey, int maxRecipients = DEFAULT_MAX)
		{
			if (maxRecipients < 1 || maxRecipients > 255)
			{
				throw new ArgumentOutOfRangeException("max recipients must be between 1 and 255.");
			}

			var nonce = SubArray(cypherText, 0, 24);
			var onetime_pk = SubArray(cypherText, 24, 32);
			var my_key = ScalarMult.Mult(secretKey, onetime_pk);
			var start = 24 + 32;
			var size = 32 + 1 + 16;
			for (var i = 0; i <= maxRecipients; i++)
			{
				var s = start + size * i;

				if (s + size > (cypherText.Length - 16)) return null;

				try
				{
					var length_and_key = SecretBox.Open(SubArray(cypherText, s, size), nonce, my_key);

					if (length_and_key != null)
					{
						return length_and_key;
					}
				}
				catch (System.Security.Cryptography.CryptographicException) { }
				catch (Exception ex) { System.Diagnostics.Trace.WriteLine(ex.Message); }
			}

			return null;
		}

		/// <summary>
		/// MultiboxOpenBody
		/// </summary>
		/// <param name="cypherText"></param>
		/// <param name="length_and_key"></param>
		/// <returns></returns>
		public static byte[] MultiboxOpenBody(byte[] cypherText, byte[] length_and_key)
		{
			if (length_and_key == null) return null;
			var key = SubArray(length_and_key, 1, length_and_key.Length - 1);
			var length = length_and_key[0];
			var start = 24 + 32;
			var size = 32 + 1 + 16;
			var nonce = SubArray(cypherText, 0, 24);
			return SecretBox.Open(SubArray(cypherText, start + length * size, cypherText.Length - (start + length * size)), nonce, key);
		}

		/// <summary>
		/// Attempt to decrypt a private-box message, using your secret key.
		/// If you where an intended recipient then the plaintext will be returned.
		/// If it was not for you, then 'null' will be returned.
		/// </summary>
		/// <param name="cypherText"></param>
		/// <param name="secretKey"></param>
		/// <param name="maxRecipients"></param>
		/// <returns>return null if secretKey is not valid</returns>
		public static byte[] MultiboxOpen(byte[] cypherText, byte[] secretKey, int maxRecipients = DEFAULT_MAX)
		{
			if (maxRecipients < 1 || maxRecipients > 255)
			{
				throw new ArgumentOutOfRangeException("max recipients must be between 1 and 255.");
			}

			var _key = MultiboxOpenKey(cypherText, secretKey, maxRecipients);
			return MultiboxOpenBody(cypherText, _key);
		}

		/// <summary>
		/// Attempt to decrypt a private-box message, using your secret key.
		/// If you where an intended recipient then the plaintext will be returned.
		/// If it was not for you, then 'null' will be returned.
		/// same as MultiboxOpen
		/// </summary>
		/// <param name="cypherText"></param>
		/// <param name="secretKey"></param>
		/// <param name="maxRecipients"></param>
		/// <returns>return null if secretKey is not valid</returns>
		public static byte[] Decrypt(byte[] cypherText, byte[] secretKey, int maxRecipients = DEFAULT_MAX)
		{
			return MultiboxOpen(cypherText, secretKey, maxRecipients);
		}

		private static T[] SubArray<T>(T[] data, int index, int length)
		{
			T[] result = new T[length];
			Array.Copy(data, index, result, 0, length);
			return result;
		}
	}
}
