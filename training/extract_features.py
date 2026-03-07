from bs4 import BeautifulSoup


def extract_features(html):
    soup = BeautifulSoup(html, 'html.parser')
    all_input_fields = soup.find_all('input')
    all_buttons = soup.find_all('button')
    all_forms = soup.find_all('form')
    all_script_tags = soup.find_all('script')
    maybe_body = soup.find('body')
    title_tag = soup.find('title')

    # Example features
    num_input_fields = len(all_input_fields)
    num_buttons = len(all_buttons)
    num_forms = len(all_forms)
    num_tags_within_body = 0
    if maybe_body:
        # Extract all tags within body except those within header
        tags_within_body = maybe_body.find_all(
            lambda tag: tag.name != 'header' and tag.parent.name != 'header')
        num_tags_within_body = len(tags_within_body)
    has_form_with_post = any(field.get('method') ==
                             'POST' for field in all_forms)
    has_form_with_action = any(field.get('action') for field in all_forms)
    has_password_field = any(field.get('type') == 'password' or
                             field.get('placeholder') in ['Password', 'password'] or
                             field.get('id') in ['Password', 'password'] or
                             field.get('name') in ['Password', 'password'] for field in all_input_fields)
    has_obfuscated_script = False
    for script in all_script_tags:
        script_content = script.string
        if script_content:
          # Check if script content contains both "document.write" and "unescape"
            if 'document.write' in script_content and 'unescape' in script_content:
                has_obfuscated_script = True
                break
    # use + html.count(...) for more keywords
    flagged_keywords = \
        html.count("coingrok") + \
        html.count("msftauth.net") + \
        html.count("duckdns.org") + \
        html.count("login.live.com") + \
        html.count("microsoftonline.com") + \
        html.count("microsoft.com") + \
        html.count("office.com") + \
        html.count("outlook-scoped") + \
        html.count("MSLogo") + \
        html.count("flapTriangle") + \
        html.count("#challenge-success") + \
        html.count("preventBack") + \
        html.count("<title>Sign-In</title>") + \
        html.count("Please wait...") + \
        html.count("Verifying your account details") + \
        html.count("Internal Server Error") + \
        html.count("uHost ") + \
        html.count("uhost-") + \
        html.count("siasky.net") + \
        html.count("$(\"#password\")") + \
        html.count("html('Sgn in')") + \
        html.count("super-vision.jp") + \
        html.count("checkdns.php") + \
        html.count("akamaized.net") + \
        html.count("api.telegram.org") + \
        html.count("/sendMessage") + \
        html.count("Intuit") + \
        html.count("OneDrive") + \
        html.count("Swarm Gateway")
    recpatcha = \
        html.count("recaptcha") + \
        html.count("reCAPTCHA") + \
        html.count("gstatic.com/recaptcha") + \
        html.count("challenge-platform")
    obfuscation = \
        html.count("document.write(unescape") + \
        html.count("document.write(atob") + \
        html.count("data:text/html;base64") + \
        html.count("<iframe src=\"data") + \
        html.count("iIiIiIiI")

    all_flagged_keywords = flagged_keywords + recpatcha + obfuscation

    # keyword to facilitate neutral score
    whitelisted_keywords = \
        html.count("nfca.cc") + \
        html.count("swarm-gateways.net") + \
        html.count("wikipedia.org") + \
        html.count("wikimedia.org") + \
        html.count("siasky.net") + \
        html.count("ipfs.io") + \
        html.count("mit.edu") + \
        html.count("googlier.com")

    # Title and meta analysis features
    title_text = title_tag.get_text().lower() if title_tag else ""
    title_length = len(title_text)
    html_lower = html.lower()

    # Check for password-related keywords in title
    has_password_in_title = any(keyword in title_text for keyword in [
        'password', 'enter password', 'enter your password'
    ])

    # Check for sign-in/login keywords in title
    has_signin_in_title = any(keyword in title_text for keyword in [
        'sign in', 'sign-in', 'signin', 'login', 'log in', 'log-in'
    ])

    # Check for suspicious verification/action keywords in title
    has_suspicious_title = any(keyword in title_text for keyword in [
        'verify', 'confirm', 'update', 'suspend', 'locked', 'security alert',
        'action required', 'expire', 'urgent', 'unusual activity'
    ])

    # Crypto wallet phishing detection
    crypto_keywords = \
        html_lower.count('recovery phrase') + \
        html_lower.count('seed phrase') + \
        html_lower.count('secret phrase') + \
        html_lower.count('12 word') + \
        html_lower.count('24 word') + \
        html_lower.count('mnemonic') + \
        html_lower.count('private key')

    wallet_keywords = \
        html_lower.count('coinbase') + \
        html_lower.count('metamask') + \
        html_lower.count('trust wallet') + \
        html_lower.count('exodus') + \
        html_lower.count('ledger') + \
        html_lower.count('trezor') + \
        html_lower.count('wallet connect') + \
        html_lower.count('crypto wallet')

    # Detect if title is generic/suspicious (very short or just "Document")
    has_generic_title = title_length < 15 or title_text.strip() in ['document', 'untitled', 'page', '']

    features = [
        num_input_fields,
        num_buttons,
        num_forms,
        num_tags_within_body,
        has_form_with_post,
        has_form_with_action,
        has_password_field,
        has_obfuscated_script,
        all_flagged_keywords,
        whitelisted_keywords,
        title_length,
        has_password_in_title,
        has_signin_in_title,
        has_suspicious_title,
        crypto_keywords,
        wallet_keywords,
        has_generic_title
    ]

    return features
