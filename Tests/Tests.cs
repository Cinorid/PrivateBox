using NUnit.Framework;
using System.Security.Cryptography;

namespace SSB.PrivateBox.Tests
{
	public class Tests
	{
		Keys keys;

		[SetUp]
		public void Setup()
		{
			keys = new Keys
			{
				Curve = "ed25519",
				Public = "1nf1T1tUSa43dWglCHzyKIxV61jG/EeeL1Xq1Nk8I3U=.ed25519",
				Private = "GO0Lv5BvcuuJJdHrokHoo0PmCDC/XjO/SZ6H+ddq4UvWd/VPW1RJrjd1aCUIfPIojFXrWMb8R54vVerU2TwjdQ==.ed25519",
				ID = "@1nf1T1tUSa43dWglCHzyKIxV61jG/EeeL1Xq1Nk8I3U=.ed25519"
			};
		}

		[Test]
		public void TestParseKeyFromString()
		{
			var testKey = Keys.FromString(
										@"{ curve: 'ed25519',
										  public: '1nf1T1tUSa43dWglCHzyKIxV61jG/EeeL1Xq1Nk8I3U=.ed25519',
										  private: 'GO0Lv5BvcuuJJdHrokHoo0PmCDC/XjO/SZ6H+ddq4UvWd/VPW1RJrjd1aCUIfPIojFXrWMb8R54vVerU2TwjdQ==.ed25519',
										  id: '@1nf1T1tUSa43dWglCHzyKIxV61jG/EeeL1Xq1Nk8I3U=.ed25519' }");

			Assert.AreEqual(testKey, keys);
		}
	}
}