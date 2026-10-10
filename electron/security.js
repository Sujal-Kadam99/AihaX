const path = require('path');

function isPathWithin(root, candidate) {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function validateDeepLink(rawUrl) {
  try {
    const url = new URL(rawUrl);
    const params = [...url.searchParams.keys()];
    const code = url.searchParams.get('code');
    const error = url.searchParams.get('error');
    const hasResult = Boolean(code) !== Boolean(error);
    if (url.protocol !== 'aihax:' || url.hostname !== 'auth' || url.pathname !== '/callback'
      || url.username || url.password || url.port || url.hash || !url.searchParams.has('state')
      || !url.searchParams.get('state')
      || url.searchParams.getAll('code').length > 1 || url.searchParams.getAll('error').length > 1
      || url.searchParams.getAll('state').length !== 1
      || !hasResult || params.some((key) => !['code', 'error', 'state'].includes(key))) {
      return null;
    }
    return url.href;
  } catch {
    return null;
  }
}

module.exports = { isPathWithin, validateDeepLink };
