# AuditDrivenCrypto.PrivateBox
C# (.NET Standard) implementation of the NodeJS private-box https://github.com/auditdrivencrypto/private-box

A format for encrypting a private message to many parties.
`AuditDrivenCrypto.PrivateBox` is designed according to the [auditdrivencrypto design process](https://github.com/crypto-browserify/crypto-browserify/issues/128)

## Nuget Package
https://www.nuget.org/packages/PrivateBox/

## API

### Encrypt (byte[] plaintext, byte[][] recipients)

Takes a `plaintext` Buffer of the message you want to encrypt,
and an array of recipient public keys.
Returns a message that is encrypted to all recipients
and openable by them with `PrivateBox.Decrypt`.
The `recipients` must be between 1 and 7 items long.

The encrypted length will be `56 + (recipients.Length * 33) + plaintext.Length` bytes long,
between 89 and 287 bytes longer than the plaintext.

### Decrypt (byte[] cyphertext, byte[] secretKey)

Attempt to decrypt a PrivateBox message, using your secret key.
If you where an intended recipient then the plaintext will be returned.
If it was not for you, then `null` will be returned.

## Protocol

### Encryption

`PrivateBox` generates an ephemeral curve25519 keypair that will only be used with this message (`ephemeral`),
and a random key that will be used to encrypt the plaintext body (`body_key`).
First, PrivateBox outputs the ephemeral public key, then multiplies each recipient public key
with its secret to produce ephemeral shared keys (`shared_keys[1..n]`).
Then, PrivateBox concatenates `body_key` with the number of recipients,
encrypts that to each shared key, and concatenates the encrypted body.

``` c#
public static byte[] Encrypt(byte[] msg, byte[][] recipients, int maxRecipients = DEFAULT_MAX)
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
```

## Decryption

`PrivateBox` takes the nonce and ephemeral public key,
multiplies that with your secret key, then tests each possible
recipient slot until it either decrypts a key or runs out of slots.
If it runs out of slots, the message was not addressed to you,
so `null` is returned. Else, the message is found and the body
is decrypted.

``` c#
public static byte[] Decrypt(byte[] cypherText, byte[] secretKey, int maxRecipients = DEFAULT_MAX)
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

			var key = SubArray(length_and_key, 1, length_and_key.Length - 1);
			var length = length_and_key[0];
			return SecretBox.Open(SubArray(cypherText, start + length * size, cypherText.Length - (start + length * size)), nonce, key);
		}
		catch { }
	}

	return null;
}
```

## Assumptions

Messages will be posted in public, so that the sender is likely to be known,
and everyone can read the messages. (This makes it possible to hide the recipient,
but probably not the sender.)

Resisting traffic analysis of the timing or size of messages is out of scope of this spec.

## Prior Art

### PGP

In PGP the recipient, the sender, and the subject are sent as plaintext.
If the recipient is known, then the metadata graph of who is communicating with who can be read,
which, since it is easier to analyze than the content, is important to protect.

### Sodium seal

The Sodium library provides a _seal_ function that generates an ephemeral keypair,
derives a shared key to encrypt a message, and then sends the ephemeral public key and the message.
The recipient is hidden, and it is forward secure if the sender throws out the ephemeral key.
However, it's only possible to have one recipient.

### Minilock

Minilock uses a similar approach to `PrivateBox` but does not hide the
number of recipients. In the case of a group discussion where multiple rounds
of messages are sent to everyone, this may enable an eavesdropper to deanonymize
the participiants of a discussion if the sender of each message is known.

## Properties

This protocol was designed for use with secure-scuttlebutt.
In this place, messages are placed in public, and the sender is known via a signature,
but we can hide the recipient and the content.

### Recipients are hidden.

An eaves-dropper cannot know the recipients or their number.
Since the message is encrypted to each recipient, and then placed in public,
to receive a message you will have to decrypt every message posted.
This would not be scalable if you had to decrypt every message on the internet,
but if you can restrict the number of messages you might have to decrypt,
then it's reasonable. For example, if you frequented a forum which contained these messages,
then it would only be a reasonable number of messages, and posting a message would only
reveal that you where talking to some other member of that forum.

Hiding access to such a forum is another problem that's out of the current scope.

### The number of recipients are hidden.

If the number of recipients was not hidden, then sometimes it would be possible
to deanonymise the recipients, if there was a large group discussion with
an unusual number of recipients. Encrypting the number of recipients means that
when you fail to decrypt a message you must attempt to decrypt same number of times
as the maximum recipients.

### A valid recipient does not know the other recipients.

A valid recipient knows the number of recipients but now who they are.
This is more a sideeffect of the design than an intentional design element.

### By providing the `key` for a message a outside party could decrypt the message.

When you tell someone a secret you must trust them not to reveal it.
Anyone who knows the `key` could reveal that to some other party who could then read the message content,
but not the recipients (unless the sender revealed the ephemeral secret key).

## License

MIT

Package Icon: https://www.flaticon.com/free-icon/key_3039392
