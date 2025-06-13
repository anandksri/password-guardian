// Password Strength Calculation
const passwordInput = document.getElementById('password-input');
const strengthFill = document.getElementById('strength-fill');
const strengthText = document.getElementById('strength-text');
const breachBtn = document.getElementById('breach-check-btn');
const breachResult = document.getElementById('breach-result');
const entropyValue = document.getElementById('entropy-value');
const commonWarning = document.getElementById('common-warning');
const suggestionsList = document.getElementById('suggestions-list');
const copyBtn = document.getElementById('copy-btn');
const copyFeedback = document.getElementById('copy-feedback');
const togglePasswordBtn = document.getElementById('toggle-password');
const eyeIcon = document.getElementById('eye-icon');

const commonPasswords = [
    '123456', 'password', '123456789', '12345678', '12345', '111111', '1234567',
    'sunshine', 'qwerty', 'iloveyou', 'princess', 'admin', 'welcome', '666666',
    'abc123', 'football', '123123', 'monkey', '654321', '!@#$%^&*'
];

// Calculate entropy estimate
function calculateEntropy(str) {
    let pool = 0;
    if (/[a-z]/.test(str)) pool += 26;
    if (/[A-Z]/.test(str)) pool += 26;
    if (/[0-9]/.test(str)) pool += 10;
    if (/[^A-Za-z0-9]/.test(str)) pool += 32; // Symbols approx
    return str.length * Math.log2(pool);
}

function updateStrength(password) {
    let score = 0;
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;

    // Normalize to max 5
    if (score > 5) score = 5;
    return score;
}

function getStrengthLabel(score) {
    switch (score) {
        case 0: return 'Too weak';
        case 1: return 'Very Weak';
        case 2: return 'Weak';
        case 3: return 'Medium';
        case 4: return 'Strong';
        case 5: return 'Very Strong';
        default: return '';
    }
}

function generateSuggestions(password) {
    const suggestions = [];
    if (password.length < 12) suggestions.push('Use at least 12 characters');
    if (!/[A-Z]/.test(password)) suggestions.push('Add uppercase letters');
    if (!/[a-z]/.test(password)) suggestions.push('Add lowercase letters');
    if (!/[0-9]/.test(password)) suggestions.push('Include numbers');
    if (!/[^A-Za-z0-9]/.test(password)) suggestions.push('Add special characters');
    if (password.length > 0 && commonPasswords.includes(password.toLowerCase()))
        suggestions.push('Avoid common passwords');
    return suggestions;
}

// Convert ArrayBuffer to hex string
function buf2hex(buffer) {
    return [...new Uint8Array(buffer)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('')
        .toUpperCase();
}

// SHA-1 hash function
async function sha1(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
    return buf2hex(hashBuffer);
}

// Check breach via Have I Been Pwned API
async function checkBreach(password) {
    breachResult.textContent = 'Checking breach status... 🔄';
    breachResult.className = 'text-yellow-400 font-semibold';

    try {
        const hash = await sha1(password);
        const prefix = hash.slice(0, 5);
        const suffix = hash.slice(5);

        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        if (!response.ok) throw new Error('API error');

        const text = await response.text();
        const lines = text.split('\n');

        for (const line of lines) {
            const [hashSuffix, count] = line.split(':');
            if (hashSuffix.trim() === suffix) {
                breachResult.textContent = `⚠️ This password has been found ${parseInt(count).toLocaleString()} times in data breaches!`;
                breachResult.className = 'text-red-500 font-semibold';
                return;
            }
        }
        breachResult.textContent = '✔️ No breach found for this password.';
        breachResult.className = 'text-green-400 font-semibold';

    } catch (error) {
        let msg = '❌ Error checking breach status.';
        if (window.location.protocol === 'file:') {
            msg = '❌ Breach check does not work when opened as a file. Please use a local or online server (http/https).';
        } else if (error instanceof TypeError && navigator.onLine === false) {
            msg = '❌ No internet connection.';
        } else if (error instanceof TypeError) {
            msg = '❌ Network error. This may be due to browser or network restrictions. Try using a different browser, device, or network. Make sure you are accessing the site via http/https, not file://.';
        }
        breachResult.textContent = msg;
        breachResult.className = 'text-red-500 font-semibold';
        console.error(error);
    }
}

passwordInput.addEventListener('input', () => {
    const pass = passwordInput.value;
    if (pass.length === 0) {
        strengthFill.style.width = '0%';
        strengthFill.className = 'h-4 w-0 strength-0 transition-all duration-500';
        strengthText.textContent = 'Enter a password to see strength';
        entropyValue.textContent = '- bits';
        commonWarning.classList.add('hidden');
        suggestionsList.innerHTML = '';
        breachResult.textContent = '';
        copyFeedback.textContent = '';
        return;
    }
    const score = updateStrength(pass);
    strengthFill.style.width = (score / 5) * 100 + '%';
    strengthFill.className = `h-4 strength-${score} transition-all duration-500`;
    strengthText.textContent = getStrengthLabel(score);

    const entropy = calculateEntropy(pass);
    entropyValue.textContent = entropy.toFixed(2) + ' bits';

    if (commonPasswords.includes(pass.toLowerCase())) {
        commonWarning.classList.remove('hidden');
    } else {
        commonWarning.classList.add('hidden');
    }

    // Suggestions
    const suggs = generateSuggestions(pass);
    suggestionsList.innerHTML = '';
    if (suggs.length === 0) {
        suggestionsList.innerHTML = '<li>Great! Your password looks strong.</li>';
    } else {
        suggs.forEach(s => {
            const li = document.createElement('li');
            li.textContent = s;
            suggestionsList.appendChild(li);
        });
    }

    breachResult.textContent = '';
    copyFeedback.textContent = '';
});

breachBtn.addEventListener('click', () => {
    const pass = passwordInput.value;
    if (pass.length === 0) {
        breachResult.textContent = 'Enter a password first.';
        breachResult.className = 'text-red-500 font-semibold';
        return;
    }
    checkBreach(pass);
});

copyBtn.addEventListener('click', () => {
    const pass = passwordInput.value;
    if (!pass) {
        copyFeedback.textContent = 'Nothing to copy!';
        copyFeedback.className = 'text-red-500 font-semibold';
        return;
    }
    // Try modern clipboard API, fallback to execCommand for mobile compatibility
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(pass).then(() => {
            copyFeedback.textContent = 'Copied to clipboard!';
            copyFeedback.className = 'text-green-400 font-semibold';
        }).catch(() => {
            copyFeedback.textContent = 'Failed to copy.';
            copyFeedback.className = 'text-red-500 font-semibold';
        });
    } else {
        // Fallback for older browsers/mobile
        const tempInput = document.createElement('input');
        tempInput.value = pass;
        document.body.appendChild(tempInput);
        tempInput.select();
        tempInput.setSelectionRange(0, 99999); // For mobile
        try {
            document.execCommand('copy');
            copyFeedback.textContent = 'Copied to clipboard!';
            copyFeedback.className = 'text-green-400 font-semibold';
        } catch (err) {
            copyFeedback.textContent = 'Failed to copy.';
            copyFeedback.className = 'text-red-500 font-semibold';
        }
        document.body.removeChild(tempInput);
    }
});

if (togglePasswordBtn && passwordInput) {
    togglePasswordBtn.addEventListener('click', function () {
        const isPassword = passwordInput.type === 'password';
        passwordInput.type = isPassword ? 'text' : 'password';
        // Toggle eye icon (open/closed)
        eyeIcon.innerHTML = isPassword
            ? '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.418 0-8-3.134-8-7a6.978 6.978 0 012.316-5.19m3.252-2.13A9.956 9.956 0 0112 5c4.418 0 8 3.134 8 7 0 1.306-.417 2.534-1.16 3.59M15 12a3 3 0 11-6 0 3 3 0 016 0zm-6.586 6.586L19.07 4.93M4.93 4.93l14.14 14.14" />'
            : '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0zm6 0c0 3.866-3.582 7-8 7s-8-3.134-8-7 3.582-7 8-7 8 3.134 8 7z" />';
    });
}

// Initialize lucide icons
document.addEventListener('DOMContentLoaded', () => {
    lucide.replace();
});


