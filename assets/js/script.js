

document.addEventListener('DOMContentLoaded', () => {
    const savedTheme = localStorage.getItem('theme') || 'dark-mode';
    document.body.classList.add(savedTheme);

    const encryptionSection = document.getElementById('get-started');
    const algorithms = ['AES', 'Blowfish', 'RSA', 'Hybrid'];
    const descriptions = {
        'AES': 'AES (Advanced Encryption Standard) is a symmetric encryption algorithm widely used for securing sensitive data. AES was established as the standard encryption algorithm by the National Institute of Standards and Technology (NIST) in 2001. It supports key lengths of 128, 192, and 256 bits. AES is known for its efficiency in both hardware and software, making it suitable for a wide range of applications. AES is extensively used in protocols like TLS and SSL to secure internet communications, and in VPNs, disk encryption software, and file protection systems. AES encryption operates by using the same key for both encryption and decryption, making it faster than asymmetric encryption algorithms. It is considered highly secure and resistant to all known practical cryptographic attacks, such as brute force and differential cryptanalysis.',
        'Blowfish': 'Blowfish is a symmetric key block cipher designed by Bruce Schneier in 1993. It uses a variable-length key from 32 to 448 bits, allowing flexibility in balancing speed and security. Blowfish is particularly known for being faster than older algorithms such as DES (Data Encryption Standard), while offering better security. Its smaller block size (64 bits) compared to modern ciphers like AES (128 bits) may make it less secure against certain types of attacks in modern contexts. However, Blowfish is still a preferred option in applications requiring lightweight encryption. It was once widely used in software such as VPNs, disk encryption tools, and network security, but its 64-bit block size is increasingly seen as inadequate for applications with high data throughput or for those requiring stronger resistance to modern attack vectors.',
        'RSA': 'RSA (Rivest-Shamir-Adleman) is one of the first public-key cryptosystems, introduced in 1977. It is widely used for secure data transmission over insecure channels such as the internet. RSA relies on the difficulty of factoring large prime numbers, making it computationally hard to break with current technology. RSA is used for both encryption and digital signatures, providing authentication and confidentiality. It is one of the most widely implemented asymmetric encryption algorithms in protocols such as HTTPS, email encryption, and digital certificates. Unlike symmetric key algorithms like AES, RSA uses a pair of keys: a public key for encryption and a private key for decryption, making it suitable for secure key exchange. However, RSA is slower than symmetric encryption methods like AES, and its key sizes must be larger (typically 2048 or 4096 bits) to achieve a similar level of security.',
        'Hybrid': 'Hybrid encryption combines the strengths of both symmetric and asymmetric encryption techniques. In a hybrid system, asymmetric encryption algorithms like RSA are used to exchange symmetric keys securely, while symmetric encryption algorithms like AES or Blowfish are used to encrypt the actual data. This approach combines the best of both worlds: the efficiency of symmetric encryption for large data and the secure key distribution of asymmetric encryption. Hybrid encryption is commonly used in modern secure communication protocols such as HTTPS, where RSA or other asymmetric algorithms secure the exchange of the AES key. Once the symmetric key is exchanged, AES handles the encryption of the actual data, providing both strong security and efficient processing speed. This method is widely used because it strikes a balance between the speed of symmetric encryption and the strong security provided by asymmetric encryption, making it ideal for secure online transactions, VPNs, and secure messaging applications.'
    };

    algorithms.forEach(algo => {
        const algoBox = document.createElement('div');
        algoBox.className = 'algo-box';
        algoBox.textContent = algo + ' Encryption';
        algoBox.addEventListener('click', () => showInfo(algo, descriptions[algo]));
        encryptionSection.appendChild(algoBox);
    });
});

function showInfo(title, text) {
    document.getElementById('info-title').innerText = title;
    document.getElementById('info-text').innerText = text;
    document.getElementById('info-modal').classList.add('active');
}

function hideInfo() {
    document.getElementById('info-modal').classList.remove('active');
}