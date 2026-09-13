# Password Guardian <img src="favicons/android-chrome-192x192.png" alt="Password Guardian Logo" width="32" height="32" style="vertical-align:middle; margin-left:8px;" />

**Password Guardian** is a browser-based password security tool for checking password strength, estimating entropy, identifying common passwords, and checking whether a password appears in known breach data.

## Features

- **Real-time Password Strength Meter**: Provides immediate feedback while entering a password.
- **Show/Hide Password**: Toggle password visibility when needed.
- **Breach Detection**: Uses the Have I Been Pwned Pwned Passwords API with k-anonymity so the complete password hash is not sent to the service.
- **Password Entropy Estimate**: Provides a rough estimate based on password length and character pool size.
- **Common Password Warning**: Checks against a built-in list of commonly used passwords.
- **Smart Suggestions**: Provides practical recommendations for improving password strength.
- **Copy to Clipboard**: Copies the password for convenient use elsewhere.
- **Responsive and Accessible**: Designed for different screen sizes and accessibility needs.

## Privacy and Security

Password analysis is performed in the browser. For breach checking, the application uses the Pwned Passwords range API and sends only the first five characters of the SHA-1 password hash as required by the k-anonymity model.

The entropy value is an estimate, not a measure of actual password crack time. Password strength also depends on patterns, reuse, leaked credentials, and attacker knowledge.

Do not enter real passwords that you are currently using for important accounts into security tools unless you understand and accept the associated risks. A password manager is recommended for generating and storing unique passwords.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Getting Started

Clone the repository:

```sh
git clone https://github.com/anandksri/password-guardian.git
cd password-guardian
```

Open `index.html` in a browser. No build step is required for the current version.

## Project Structure

```text
index.html                 Main application page
css/style.css              Custom styles
js/script.js               Application logic
favicons/                  App icons
site.webmanifest           PWA manifest
SECURITY.md                Security reporting policy
```

## Technologies Used

- HTML5
- CSS3
- Tailwind CSS
- JavaScript (ES6+)
- Lucide Icons
- Have I Been Pwned Pwned Passwords API

## Contributing

Pull requests and improvements are welcome. For larger changes, open an issue first so the proposed change can be discussed.

When contributing security-sensitive changes, explain the security impact and include testing details where possible.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Author

- [Anand Keshari](https://anandkeshari.com.np)

## Acknowledgments

- [Have I Been Pwned](https://haveibeenpwned.com/) for breach data
- [TC Pioneer](https://tcpioneer.org) for support
