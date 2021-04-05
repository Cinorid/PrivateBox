using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;
using Rebex.Security.Cryptography;

namespace SSB.PrivateBox
{
	public static class Sodium
	{
		public static Keys Generate(byte[] seed)
		{
			if (seed == null)
			{
				Random rnd = new Random();
				seed = new byte[32]; // convert kb to byte
				rnd.NextBytes(seed);
			}

			Ed25519 ed25519 = new Ed25519();
			ed25519.FromSeed(seed);
			var secretKey = ed25519.GetPrivateKey();
			var publicKey = ed25519.GetPublicKey();

			var _public = Convert.ToBase64String(publicKey) + ".ed25519";
			var _private = Convert.ToBase64String(secretKey) + ".ed25519";

			var keys = new Keys
			{
				Curve = "ed25519",
				Public = _public,
				Private = _private,
				ID = "@" + _public,
			};

			return keys;
		}

		public static byte[] SignMessage(byte[] privateKey, byte[] message)
		{
			Ed25519 ed25519 = new Ed25519();
			ed25519.FromPrivateKey(privateKey);
			return ed25519.SignMessage(message);
		}

		public static string SignMessage(string privateKey, string message)
		{
			var _privateKey = Convert.FromBase64String(privateKey.Replace(".ed25519", ""));
			var _message = Convert.FromBase64String(message.Replace(".ed25519", ""));

			return Convert.ToBase64String(SignMessage(_privateKey, _message)) + ".ed25519";
		}

		public static bool VerifyMessage(byte[] publicKey, byte[] message, byte[] sign)
		{
			Ed25519 ed25519 = new Ed25519();
			ed25519.FromPublicKey(publicKey);
			return ed25519.VerifyMessage(message, sign);
		}
	}
}
