const { URL } = require('url');

function getUpdateReadiness({ isPackaged, platform, config }) {
  if (!isPackaged) {
    return { enabled: false, reason: 'Updates are disabled for development builds.' };
  }
  if (platform !== 'win32') {
    return { enabled: false, reason: 'This release channel supports Windows updates only.' };
  }
  if (!config || typeof config !== 'object' || config.provider !== 'generic') {
    return { enabled: false, reason: 'A configured generic update feed is required.' };
  }

  let feedUrl;
  try {
    feedUrl = new URL(config.url);
  } catch {
    return { enabled: false, reason: 'The update feed URL is invalid.' };
  }
  if (
    feedUrl.protocol !== 'https:' ||
    !feedUrl.hostname ||
    feedUrl.username ||
    feedUrl.password ||
    feedUrl.search ||
    feedUrl.hash
  ) {
    return { enabled: false, reason: 'The update feed must be a credential-free HTTPS URL.' };
  }

  const publisherNames = Array.isArray(config.publisherName)
    ? config.publisherName
    : [config.publisherName];
  if (!publisherNames.some((name) => typeof name === 'string' && name.trim())) {
    return { enabled: false, reason: 'A trusted Windows code-signing publisher is required.' };
  }

  return { enabled: true, feedUrl: feedUrl.toString(), publisherNames };
}

module.exports = { getUpdateReadiness };
