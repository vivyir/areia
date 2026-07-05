# Areia

UDP-based AES-GCM encrypted secure communications channel built in a cave with a box of scraps. Functional but bare minimum for simplicity's sake; don't expect a competitor to the matrix protocol.

Uses a server-client architecture because peer-to-peer was deemed unfeasible and completely unrealistic under hostile network conditions. Those who know use UPnP with a supported ISP.

Derives key using two SHA-1 steps because it was the only available algorithm, any random 32 bytes that you can share out of band works.

## How do I run it?

Compile it as "areia".

First of all, derive the key from a passphrase. This makes a file named "key" in the current working directory. You'll need to have this file in your working directory where you run areia, be it the server or clients.
`areia key`

For running the server, you can use:
`areia server`
Choose a port. The way you expose them is none of my business.

To run the client, you'd have to attach the sender and listener separately. Sender sends messages, listener gets them.
`areia listener`
And for sender:
`areia sender`

It'll ask you the relevant information when required. I don't recommend running the CLI, my friend wrote an Android app that makes the interface actually bearable. Use [Apollo](https://github.com/KasraIDK/apollo) if you don't want to lose your mind while using this.

## How do I use it?

It is assumed that if you have the cryptographic key to join a server that you are trusted. Be trustworthy.

You'll send messages by writing them in the server, but for a lot of commands to work you'll need to be nicknamed.

Set a nick with `/setnick Pezeshkian`, assuming your nickname is Pezeshkian.

You can also set your status with `/status away from keyboard`, assuming you're away from keyboard.

Check the list of currently connected users and their last interaction with the server using `/list`.

Or use the classic `/me is not having any of this.` to output "* Pezeshkian is not having any of this."

There are also memos with a maximum of 10 memos at once. They're messages every listener will receive upon joining.

New memo: `/memo <text>`

View memos again: `/viewmemo`

Clear all memos: `/clearmemos`

If people's IPs change a lot, you should also periodically run `/attrition`.

## Is it secure?

Yes, but I would use something like Argon2id to derive the key instead; then it would be as secure as your method for sharing the passphrase used to derive the AES key. See also: operational security.

## Does it have an IP based or CIDR range whitelist?

Anybody asking this question after reading the scope of this program should:
- Re-evaluate their life choices.
- Educate themselves on networks and cryptography.
- Obtain common sense.
