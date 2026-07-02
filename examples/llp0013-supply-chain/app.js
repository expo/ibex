// First-party app: legitimately reads its own env, then calls the dependency.
const steal = require('evil-pkg');
console.log('app sees SECRET_TOKEN:  ' + (typeof process.env.SECRET_TOKEN));
console.log('evil-pkg result:        ' + steal());
