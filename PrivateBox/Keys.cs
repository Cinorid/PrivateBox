using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;

namespace SSB.PrivateBox
{
	/// <summary>
	/// keyfile operations for ssb
	/// </summary>
	public class Keys
	{
		[JsonProperty("curve")]
		public string Curve { get; set; } = "ed25519";

		[JsonProperty("public")]
		public string Public { get; set; }

		[JsonProperty("private")]
		public string Private { get; set; }

		[JsonProperty("id")]
		public string ID { get; set; }

		/// <summary>
		/// check to see if to SSB keys are the same.
		/// </summary>
		/// <param name="keys">target SSB keys</param>
		/// <returns>result of equality</returns>
		public override bool Equals(object keys)
		{
			if (keys != null)
			{
				if (keys.GetHashCode() == GetHashCode())
				{
					return true;
				}
			}

			return false;
		}

		/// <summary>
		/// A simple algorithm to distinguish between two SSB keys.
		/// </summary>
		/// <returns>Numeric hash</returns>
		public override int GetHashCode()
		{
			int hashCode = 0;

			unchecked
			{
				if (Curve != null)
				{
					foreach (char c in Curve)
					{
						hashCode = hashCode * c.GetHashCode();
					}
				}

				if (Public != null)
				{
					foreach (char c in Public)
					{
						hashCode = hashCode * c.GetHashCode();
					}
				}

				if (Private != null)
				{
					foreach (char c in Private)
					{
						hashCode = hashCode * c.GetHashCode();
					}
				}

				if (ID != null)
				{
					foreach (char c in ID)
					{
						hashCode = hashCode * c.GetHashCode();
					}
				}

				return hashCode;
			}
		}

		/// <summary>
		/// Converts SSB keys to a indented Json string
		/// </summary>
		/// <returns>Equivalent Json string</returns>
		public override string ToString()
		{
			return Keys.ToString(this);
		}

		/// <summary>
		/// Converts SSB keys to a indented Json string
		/// </summary>
		/// <param name="keys">SSB keys object</param>
		/// <returns>Equivalent Json string</returns>
		public static string ToString(Keys keys)
		{
			if (keys != null)
			{
				return JsonConvert.SerializeObject(keys, Formatting.Indented);
			}

			return null;
		}

		/// <summary>
		/// Converts a Json string to SSB keys
		/// </summary>
		/// <param name="text">Json string</param>
		/// <returns>Equivalent SSB keys</returns>
		public static Keys FromString(string text)
		{
			if (!string.IsNullOrEmpty(text))
			{
				return (Keys)JsonConvert.DeserializeObject(text, typeof(Keys));
			}

			return null;
		}
	}
}
