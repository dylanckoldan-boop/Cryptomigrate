const crypto = require('crypto');
const c = crypto.createCipheriv('des-ede3-cbc', key, iv);
const t = CryptoJS.TripleDES.encrypt(message, secret);
